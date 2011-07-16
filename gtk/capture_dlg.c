/* capture_dlg.c
 * Routines for packet capture windows
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <stdio.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/filesystem.h>

#include "../capture.h"
#include "../capture_errs.h"
#include "../capture_ifinfo.h"
#include "../simple_dialog.h"
#include "../capture-pcap-util.h"
#include "../capture_ui_utils.h"
#include "../ringbuffer.h"

#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/gui_utils.h"
#include "gtk/capture_dlg.h"
#include "gtk/filter_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/file_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/capture_globals.h"
#include "gtk/cfilter_combo_utils.h"

#ifdef _WIN32
#include "../capture-wpcap.h"
#endif

#include "gtk/keys.h"

#ifdef HAVE_AIRPCAP
#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"
#include "airpcap_dlg.h"
#endif

/* Capture callback data keys */
#define E_CAP_IFACE_KEY                 "cap_iface"
#define E_CAP_IFACE_IP_KEY              "cap_iface_ip"
#define E_CAP_SNAP_CB_KEY               "cap_snap_cb"
#define E_CAP_LT_CBX_KEY                "cap_lt_cbx"
#define E_CAP_LT_CBX_LABEL_KEY          "cap_lt_cbx_label"
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
#define E_CAP_BUFFER_SIZE_SB_KEY        "cap_buffer_size_sb"
#endif
#define E_CAP_SNAP_SB_KEY               "cap_snap_sb"
#define E_CAP_PROMISC_KEY               "cap_promisc"
#ifdef HAVE_PCAP_CREATE
#define E_CAP_MONITOR_KEY               "cap_monitor"
#endif
#define E_CAP_PCAP_NG_KEY               "cap_pcap_ng"
#define E_CAP_FILT_KEY                  "cap_filter_te"
#define E_CAP_FILE_TE_KEY               "cap_file_te"
#define E_CAP_MULTI_FILES_ON_CB_KEY     "cap_multi_files_on_cb"
#define E_CAP_RING_FILESIZE_CB_KEY      "cap_ring_filesize_cb"
#define E_CAP_RING_FILESIZE_SB_KEY      "cap_ring_filesize_sb"
#define E_CAP_RING_FILESIZE_CBX_KEY     "cap_ring_filesize_cbx"
#define E_CAP_FILE_DURATION_CB_KEY      "cap_file_duration_cb"
#define E_CAP_FILE_DURATION_SB_KEY      "cap_file_duration_sb"
#define E_CAP_FILE_DURATION_CBX_KEY     "cap_file_duration_cbx"
#define E_CAP_RING_NBF_CB_KEY           "cap_ring_nbf_cb"
#define E_CAP_RING_NBF_SB_KEY           "cap_ring_nbf_sb"
#define E_CAP_RING_NBF_LB_KEY           "cap_ring_nbf_lb"
#define E_CAP_STOP_FILES_CB_KEY         "cap_stop_files_cb"
#define E_CAP_STOP_FILES_SB_KEY         "cap_stop_files_sb"
#define E_CAP_STOP_FILES_LB_KEY         "cap_stop_files_lb"
#define E_CAP_SYNC_KEY                  "cap_sync"
#define E_CAP_AUTO_SCROLL_KEY           "cap_auto_scroll"
#define E_CAP_HIDE_INFO_KEY             "cap_hide_info"
#define E_CAP_STOP_PACKETS_CB_KEY       "cap_stop_packets_cb"
#define E_CAP_STOP_PACKETS_SB_KEY       "cap_stop_packets_sb"
#define E_CAP_STOP_PACKETS_LB_KEY       "cap_stop_packets_lb"
#define E_CAP_STOP_FILESIZE_CB_KEY      "cap_stop_filesize_cb"
#define E_CAP_STOP_FILESIZE_SB_KEY      "cap_stop_filesize_sb"
#define E_CAP_STOP_FILESIZE_CBX_KEY     "cap_stop_filesize_cbx"
#define E_CAP_STOP_DURATION_CB_KEY      "cap_stop_duration_cb"
#define E_CAP_STOP_DURATION_SB_KEY      "cap_stop_duration_sb"
#define E_CAP_STOP_DURATION_CBX_KEY     "cap_stop_duration_cbx"
#define E_CAP_M_RESOLVE_KEY             "cap_m_resolve"
#define E_CAP_N_RESOLVE_KEY             "cap_n_resolve"
#define E_CAP_T_RESOLVE_KEY             "cap_t_resolve"

#ifdef HAVE_PCAP_REMOTE
#define E_CAP_IFTYPE_CBX_KEY            "cap_iftype_cbx"
#define E_CAP_IF_LIST_KEY               "cap_if_list"
#define E_CAP_DATATX_UDP_CB_KEY         "cap_datatx_udp_cb"
#define E_CAP_NOCAP_RPCAP_CB_KEY        "cap_nocap_rpcap_cb"
#define E_CAP_REMOTE_DIALOG_PTR_KEY     "cap_remote_dialog"
#define E_CAP_REMOTE_CALLER_PTR_KEY     "cap_remote_caller"
#define E_REMOTE_HOST_TE_KEY            "cap_remote_host"
#define E_REMOTE_PORT_TE_KEY            "cap_remote_port"
#define E_REMOTE_AUTH_NULL_KEY          "cap_remote_auth_null"
#define E_REMOTE_AUTH_PASSWD_KEY        "cap_remote_auth_passwd"
#define E_REMOTE_USERNAME_LB_KEY        "cap_remote_username_lb"
#define E_REMOTE_USERNAME_TE_KEY        "cap_remote_username_te"
#define E_REMOTE_PASSWD_LB_KEY          "cap_remote_passwd_lb"
#define E_REMOTE_PASSWD_TE_KEY          "cap_remote_passwd_te"
#define E_CAP_CBX_IFTYPE_VALUE_KEY      "cap_cbx_iftype_value"
#define E_CAP_CBX_PREV_IFTYPE_VALUE_KEY "cap_cbx_prev_iftype_value"
#define E_CAP_CBX_IFTYPE_NOUPDATE_KEY   "cap_cbx_iftype_noupdate"
#define E_OPT_REMOTE_BT_KEY             "cap_remote_opt_bt"
#define E_OPT_REMOTE_DIALOG_PTR_KEY     "cap_remote_opt_dialog"
#define E_OPT_REMOTE_CALLER_PTR_KEY     "cap_remote_opt_caller"
#endif
#ifdef HAVE_PCAP_SETSAMPLING
#define E_CAP_SAMP_NONE_RB_KEY          "cap_samp_none_rb"
#define E_CAP_SAMP_COUNT_RB_KEY         "cap_samp_count_rb"
#define E_CAP_SAMP_COUNT_SB_KEY         "cap_samp_count_sb"
#define E_CAP_SAMP_TIMER_RB_KEY         "cap_samp_timer_rb"
#define E_CAP_SAMP_TIMER_SB_KEY         "cap_samp_timer_sb"
#endif

#define DUMMY_SNAPLENGTH                65535
#define DUMMY_NETMASK                   0xFF000000

/*
 * Keep a static pointer to the current "Capture Options" window, if
 * any, so that if somebody tries to do "Capture:Options" while there's
 * already a "Capture Options" window up, we just pop up the existing
 * one, rather than creating a new one.
 * Also: Capture:Start obtains info from the "Capture Options" window
 *       if it exists and if its creation is complete.
 */
static GtkWidget *cap_open_w = NULL;
static gboolean   cap_open_complete;  /* valid only if cap_open_w != NULL */

static GHashTable *cap_settings_history=NULL;

#ifdef HAVE_PCAP_REMOTE
static GHashTable *remote_host_list=NULL;
#endif

static void
capture_prep_file_cb(GtkWidget *file_bt, GtkWidget *file_te);

static void
select_link_type_cb(GtkWidget *w, gpointer data);

#ifdef HAVE_PCAP_REMOTE
static void
select_if_type_cb(GtkComboBox *iftype_cbx, gpointer data);

static void
capture_remote_cb(GtkWidget *w, gboolean focus_username);
#endif

static void
capture_cancel_cb(GtkWidget *win, gpointer data);

static void
capture_prep_adjust_sensitivity(GtkWidget *tb, gpointer parent_w);

static void
capture_prep_destroy_cb(GtkWidget *win, gpointer user_data);

static void
capture_prep_interface_changed_cb(GtkWidget *entry, gpointer argp);

#ifdef HAVE_PCAP_CREATE
static void
capture_prep_monitor_changed_cb(GtkWidget *monitor_cb, gpointer argp);
#endif

static gboolean
capture_dlg_prep(gpointer parent_w);


/* stop the currently running capture */
void
capture_stop_cb(GtkWidget *w _U_, gpointer d _U_)
{
#ifdef HAVE_AIRPCAP
  airpcap_set_toolbar_stop_capture(airpcap_if_active);
#endif

  capture_stop(&global_capture_opts);
}

/* restart (stop - delete old file - start) running capture */
void
capture_restart_cb(GtkWidget *w _U_, gpointer d _U_)
{
#ifdef HAVE_AIRPCAP
  airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif

  capture_restart(&global_capture_opts);
}

cap_settings_t
capture_get_cap_settings (gchar *if_name)
{
  cap_settings_t cap_settings, *cap_settings_p;

  if (cap_settings_history) {
    cap_settings_p = g_hash_table_lookup(cap_settings_history, if_name);
  } else {
    cap_settings_p = NULL;
  }

  if (cap_settings_p) {
    cap_settings = *cap_settings_p;
  } else {
    cap_settings.monitor_mode = prefs_capture_device_monitor_mode(if_name);
    cap_settings.linktype = capture_dev_user_linktype_find(if_name);;
  }

  return cap_settings;
}

static void
capture_filter_check_syntax_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
  struct bpf_program fcode;
  GtkWidget *filter_cm, *filter_te;
  const gchar *filter_text;

  if (!prefs.capture_syntax_check_filter)
    return;

  filter_cm = g_object_get_data(G_OBJECT(top_level), E_CFILTER_CM_KEY);
  filter_te = gtk_bin_get_child(GTK_BIN(filter_cm));
#if GTK_CHECK_VERSION(2,24,0)
  filter_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(filter_cm));
#else
  filter_text = gtk_combo_box_get_active_text (GTK_COMBO_BOX(filter_cm));
#endif /*GTK_CHECK_VERSION(2,24,0)*/
  if (strlen(filter_text) == 0) {
    colorize_filter_te_as_empty(filter_te);
    return;
  }

  /* pcap_compile_nopcap will not alter the filter string, so the (char *) cast is "safe" */
  if (pcap_compile_nopcap(DUMMY_SNAPLENGTH /* use a dummy snaplength for syntax-checking */,
          g_array_index(global_capture_opts.ifaces, interface_options, 0).linktype, &fcode, (char *)filter_text, 1 /* Do optimize */,
          DUMMY_NETMASK /* use a dummy netmask for syntax-checking */) < 0) {
    colorize_filter_te_as_invalid(filter_te);
  } else {
    colorize_filter_te_as_valid(filter_te);
  }
}

/*
 * Set the sensitivity of the monitor mode button, and set the
 * link-layer header type list, based on the interface's capabilities.
 *
 * The link-layer header type list often has only one entry; in that case,
 * it will be disabled.
 */
static void
set_if_capabilities(gboolean monitor_mode_changed)
{
  gchar *entry_text;
  gchar *if_text;
  gchar *if_name;
  GList *if_list;
  GList *if_entry;
  if_info_t *if_info;
  if_capabilities_t *caps;
  int err;
  GList *lt_entry;
  cap_settings_t cap_settings;
  gint linktype_select, linktype_count;
  data_link_info_t *data_link_info;
  guint num_supported_link_types;
  GtkWidget *linktype_combo_box = (GtkWidget *) g_object_get_data(G_OBJECT(cap_open_w), E_CAP_LT_CBX_KEY);
  GtkWidget *linktype_lb = g_object_get_data(G_OBJECT(linktype_combo_box), E_CAP_LT_CBX_LABEL_KEY);
  GtkWidget *if_ip_lb;
  GString *ip_str = g_string_new("IP address: ");
  int ips = 0;
  GSList *curr_addr;
  if_addr_t *addr;
  GtkWidget *if_cb = (GtkWidget *) g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IFACE_KEY);
#ifdef HAVE_PCAP_REMOTE
  GtkWidget *iftype_cbx;
  int iftype;
#endif
#ifdef HAVE_PCAP_CREATE
  GtkWidget *monitor_cb = (GtkWidget *) g_object_get_data(G_OBJECT(cap_open_w), E_CAP_MONITOR_KEY);
#endif
#ifdef HAVE_AIRPCAP
  GtkWidget *advanced_bt;
#endif

  interface_options interface_opts;
#if GTK_CHECK_VERSION(2,24,0)
  entry_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(if_cb));
#else
  entry_text = gtk_combo_box_get_active_text (GTK_COMBO_BOX(if_cb));
#endif /* GTK_CHECK_VERSION(2,24,0) */

  if(!entry_text)
    entry_text = '\0';

  if_text = g_strstrip(entry_text);
  if_name = g_strdup(get_if_name(if_text));
  cap_settings = capture_get_cap_settings(if_name);
  if (monitor_mode_changed) {
#ifdef HAVE_PCAP_CREATE
    /* Get the new setting of the monitor mode button. */
    cap_settings.monitor_mode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(monitor_cb));
#else
    /* No monitor-mode support. */
    cap_settings.monitor_mode = FALSE;
#endif
  }

#ifdef HAVE_AIRPCAP
  /* is it an airpcap interface??? */
  /* retrieve the advanced button pointer */
  advanced_bt = g_object_get_data(G_OBJECT(gtk_bin_get_child(GTK_BIN(if_cb))),AIRPCAP_OPTIONS_ADVANCED_KEY);
  airpcap_if_selected = get_airpcap_if_from_name(airpcap_if_list,if_name);
  airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
  if (airpcap_if_selected != NULL) {
    gtk_widget_set_sensitive(advanced_bt,TRUE);
  } else {
    gtk_widget_set_sensitive(advanced_bt,FALSE);
  }
#endif

  /*
   * If the interface name is in the list of known interfaces, get
   * its list of link-layer types and set the combo_box to display it.
   *
   * If it's not, don't bother - the user might be in the middle of
   * editing the list, or it might be a remote device in which case
   * getting the list could take an arbitrarily-long period of time.
   * The list currently won't contain any remote devices (as
   * "pcap_findalldevs()" doesn't know about remote devices, and neither
   * does the code we use if "pcap_findalldevs()" isn't available), but
   * should contain all the local devices on which you can capture.
   */
  caps = NULL;
  if (*if_name != '\0') {
    /*
     * Try to get the list of known interfaces.
     */
#ifdef HAVE_PCAP_REMOTE
    iftype_cbx = g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IFTYPE_CBX_KEY);
    iftype = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                               E_CAP_CBX_IFTYPE_VALUE_KEY));
    if (iftype >= CAPTURE_IFREMOTE)
      if_list = (GList *) g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY);
    else
      if_list = capture_interface_list(&err, NULL);   /* Warning: see capture_prep_cb() */
#else
    if_list = capture_interface_list(&err, NULL);     /* Warning: see capture_prep_cb() */
#endif
    if (if_list != NULL) {
      /*
       * We have the list - check it.
       */
      for (if_entry = if_list; if_entry != NULL;
           if_entry = g_list_next(if_entry)) {
        if_info = if_entry->data;
        if (strcmp(if_info->name, if_name) == 0) {
          /*
           * It's in the list.
           * Get the interface capabilities for it.
           */
#ifdef HAVE_PCAP_REMOTE
          if (iftype == CAPTURE_IFREMOTE) {
            /* Not able to get interface capabilities for remote interfaces */
            caps = NULL;
          } else
#endif
          caps = capture_get_if_capabilities(if_name, cap_settings.monitor_mode,
                                             NULL);

#if 0 /* for testing: Add an "unsupported" link-type */
          if (caps != NULL) {
            data_link_info_t *foo = g_malloc(sizeof (data_link_info_t));
            foo->dlt = 150;
            foo->name = g_strdup("Bar");
            foo->description = NULL;
            caps->data_link_types = g_list_append(caps->data_link_types, foo);
          }
#endif

          /* create string of list of IP addresses of this interface */
          for (; (curr_addr = g_slist_nth(if_info->addrs, ips)) != NULL; ips++) {
            if (ips != 0)
              g_string_append(ip_str, ", ");

            addr = (if_addr_t *)curr_addr->data;
            switch (addr->ifat_type) {

            case IF_AT_IPv4:
              g_string_append(ip_str, ip_to_str((guint8 *)&addr->addr.ip4_addr));
              break;

            case IF_AT_IPv6:
              g_string_append(ip_str,  ip6_to_str((struct e_in6_addr *)&addr->addr.ip6_addr));
              break;

            default:
              /* In case we add non-IP addresses */
              break;
            }
          }

          if (if_info->loopback)
            g_string_append(ip_str, " (loopback)");
        }
      }
#ifdef HAVE_PCAP_REMOTE
      /* Only delete if fetched local */
      if (iftype == CAPTURE_IFLOCAL)
#endif
      free_interface_list(if_list);
    }
  }
  g_free(entry_text);
  g_free(if_name);

  /* -- (Re)Create LinkType GtkComboBox entries -- */
  /* Deallocate the existing GtkComboBox entries for Datalink header type */
  g_signal_handlers_disconnect_by_func(linktype_combo_box, G_CALLBACK(select_link_type_cb), NULL );
  ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(linktype_combo_box));

  num_supported_link_types = 0;
  linktype_select = 0;
  linktype_count = 0;
  if (caps != NULL) {
#ifdef HAVE_PCAP_CREATE
    gtk_widget_set_sensitive(monitor_cb, caps->can_set_rfmon);
#endif
    for (lt_entry = caps->data_link_types; lt_entry != NULL;
         lt_entry = g_list_next(lt_entry)) {
      data_link_info = lt_entry->data;
      if (data_link_info->description != NULL) {
        ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(linktype_combo_box),
                                             data_link_info->description,
                                             GINT_TO_POINTER(data_link_info->dlt));

        num_supported_link_types++;
      } else {
        gchar *str;
        /* Not supported - tell them about it but don't let them select it. */
        str = g_strdup_printf("%s (not supported)", data_link_info->name);
        ws_combo_box_append_text_and_pointer_full(GTK_COMBO_BOX(linktype_combo_box),
                                                  NULL,
                                                  str,
                                                  GINT_TO_POINTER(-1),  /* Flag as "not supported" */
                                                  FALSE);
        g_free(str);
      }
      interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
      global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
      if (linktype_count==0) {
        /* default to first dlt of the interface */
        interface_opts.linktype = data_link_info->dlt;
      } else if (data_link_info->dlt == cap_settings.linktype) {
        /* Found a matching dlt, select this */
        linktype_select = linktype_count;
        interface_opts.linktype = data_link_info->dlt;
      }
      g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
      linktype_count++;
    } /* for (lt_entry = ... */
    free_if_capabilities(caps);
  }
#ifdef HAVE_PCAP_CREATE
  else {
    /* We don't know whether this supports monitor mode or not;
       don't ask for monitor mode. */
    gtk_widget_set_sensitive(monitor_cb, FALSE);
    cap_settings.monitor_mode = FALSE;
  }
#endif
  if (linktype_count == 0) {
    ws_combo_box_append_text_and_pointer_full(GTK_COMBO_BOX(linktype_combo_box),
                                              NULL,
                                              "not supported",
                                              GINT_TO_POINTER(-1),  /* Flag as "not supported" */
                                              FALSE);
  }
  gtk_widget_set_sensitive(linktype_lb, num_supported_link_types >= 2);
  gtk_widget_set_sensitive(linktype_combo_box, num_supported_link_types >= 2);

#ifdef HAVE_PCAP_CREATE
  /* Set the monitor-mode checkbox to the appropriate value */
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(monitor_cb),
                               cap_settings.monitor_mode);
#endif
  /* Restore the menu to the last index used */
  ws_combo_box_set_active(GTK_COMBO_BOX(linktype_combo_box),linktype_select);
  g_signal_connect(linktype_combo_box, "changed", G_CALLBACK(select_link_type_cb), NULL);

  if_ip_lb = g_object_get_data(G_OBJECT(linktype_combo_box), E_CAP_IFACE_IP_KEY);
  if(ips == 0) {
    g_string_append(ip_str, "unknown");
  }
  gtk_label_set_text(GTK_LABEL(if_ip_lb), ip_str->str);
  gtk_label_set_ellipsize(GTK_LABEL(if_ip_lb), PANGO_ELLIPSIZE_MIDDLE);
  g_string_free(ip_str, TRUE);
}


#define TIME_UNIT_SECOND    0
#define TIME_UNIT_MINUTE    1
#define TIME_UNIT_HOUR      2
#define TIME_UNIT_DAY       3
#define MAX_TIME_UNITS 4
static const char *time_unit_name[MAX_TIME_UNITS] = {
  "second(s)",
  "minute(s)",
  "hour(s)",
  "day(s)",
};

/* create one of the duration options */
/* (and select the matching unit depending on the given value) */
static GtkWidget *time_unit_combo_box_new(guint32 value) {
  GtkWidget *unit_combo_box;
  int i;
#if GTK_CHECK_VERSION(2,24,0)
  unit_combo_box = gtk_combo_box_text_new ();
  for(i = 0; i < MAX_TIME_UNITS; i++) {
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (unit_combo_box), time_unit_name[i]);
  }
#else
  unit_combo_box = gtk_combo_box_new_text ();
  for(i = 0; i < MAX_TIME_UNITS; i++) {
    gtk_combo_box_append_text (GTK_COMBO_BOX (unit_combo_box), time_unit_name[i]);
  }
#endif
  /* the selected combo_box item can't be changed, once the combo_box
     is created, so set the matching combo_box item now */
  /* days */
  if(value >= 60 * 60 * 24) {
    gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), TIME_UNIT_DAY);
  } else {
    /* hours */
    if(value >= 60 * 60) {
      gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), TIME_UNIT_HOUR);
    } else {
      /* minutes */
      if(value >= 60) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), TIME_UNIT_MINUTE);
      } else {
        /* seconds */
        gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), TIME_UNIT_SECOND);
      }
    }
  }
  return unit_combo_box;
}

/* convert time value from raw to displayed (e.g. 60s -> 1min) */
static guint32 time_unit_combo_box_convert_value(
guint32 value)
{
  /* days */
  if(value >= 60 * 60 * 24) {
    return value / (60 * 60 * 24);
  }

  /* hours */
  if(value >= 60 * 60) {
    return value / (60 * 60);
  }

  /* minutes */
  if(value >= 60) {
    return value / 60;
  }

  /* seconds */
  return value;
}

/* get raw value from unit and value fields */
static guint32 time_unit_combo_box_get_value(
GtkWidget *unit_combo_box,
guint32 value)
{
  int unit;

  unit = gtk_combo_box_get_active (GTK_COMBO_BOX(unit_combo_box));

  switch(unit) {
  case(TIME_UNIT_SECOND):
    return value;
  case(TIME_UNIT_MINUTE):
    return value * 60;
  case(TIME_UNIT_HOUR):
    return value * 60 * 60;
  case(TIME_UNIT_DAY):
    return value * 60 * 60 * 24;
  default:
    g_assert_not_reached();
    return 0;
  }
}


#define SIZE_UNIT_KILOBYTES 0
#define SIZE_UNIT_MEGABYTES 1
#define SIZE_UNIT_GIGABYTES 2
#define MAX_SIZE_UNITS 3
static const char *size_unit_name[MAX_SIZE_UNITS] = {
  "kilobyte(s)",
  "megabyte(s)",
  "gigabyte(s)",
};

/* create one of the size options */
/* (and select the matching unit depending on the given value) */
static GtkWidget *size_unit_combo_box_new(guint32 value) {
  GtkWidget *unit_combo_box;
  int i;
#if GTK_CHECK_VERSION(2,24,0)
  unit_combo_box=gtk_combo_box_text_new();
  for(i=0;i<MAX_SIZE_UNITS;i++){
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (unit_combo_box), size_unit_name[i]);
  }

#else
  unit_combo_box=gtk_combo_box_new_text();
  for(i=0;i<MAX_SIZE_UNITS;i++){
    gtk_combo_box_append_text (GTK_COMBO_BOX (unit_combo_box), size_unit_name[i]);
  }
#endif /*GTK_CHECK_VERSION(2,24,0)*/

  /* the selected combo_box item can't be changed, once the combo_box
     is created, so set the matching combo_box item now */
  /* gigabytes */
  if(value >= 1024 * 1024) {
    gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), SIZE_UNIT_GIGABYTES);
  } else {
    /* megabytes */
    if(value >= 1024) {
      gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), SIZE_UNIT_MEGABYTES);
    } else {
      /* kilobytes */
      gtk_combo_box_set_active(GTK_COMBO_BOX(unit_combo_box), SIZE_UNIT_KILOBYTES);
    }
  }
  return unit_combo_box;
}

/* convert size value from raw to displayed (e.g. 1024 Bytes -> 1 KB) */
static guint32 size_unit_combo_box_set_value(
guint32 value)
{
  /* gigabytes */
  if(value >= 1024 * 1024) {
    return value / (1024 * 1024);
  }

  /* megabytes */
  if(value >= 1024) {
    return value / (1024);
  }

  /* kilobytes */
  return value;
}

/* get raw value from unit and value fields */
static guint32 size_unit_combo_box_convert_value(
GtkWidget *unit_combo_box,
guint32 value)
{
  int unit;

  unit = gtk_combo_box_get_active (GTK_COMBO_BOX(unit_combo_box));

  switch(unit) {
  case(SIZE_UNIT_KILOBYTES):
    return value;
  case(SIZE_UNIT_MEGABYTES):
    if(value > G_MAXINT / 1024) {
      return 0;
    } else {
      return value * 1024;
    }
  case(SIZE_UNIT_GIGABYTES):
    if(value > G_MAXINT / (1024 * 1024)) {
      return 0;
    } else {
      return value * 1024 * 1024;
    }
  default:
    g_assert_not_reached();
    return 0;
  }
}

#ifdef HAVE_AIRPCAP
/*
 * Sets the toolbar before calling the advanced dialog with for the right interface
 */
static void
options_airpcap_advanced_cb(GtkWidget *w, gpointer d)
{
  int *from_widget;

  from_widget = (gint*)g_malloc(sizeof(gint));
  *from_widget = AIRPCAP_ADVANCED_FROM_OPTIONS;
  g_object_set_data(G_OBJECT(airpcap_tb),AIRPCAP_ADVANCED_FROM_KEY,from_widget);

  airpcap_if_active = airpcap_if_selected;
  airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
  display_airpcap_advanced_cb(w,d);
}
#endif

#ifdef HAVE_PCAP_REMOTE
/* PCAP interface type menu item */
struct iftype_info {
  capture_source  id;
  const char     *name;
};

/* List of available types of PCAP interface */
static struct iftype_info iftype[] = {
  { CAPTURE_IFLOCAL, "Local" },
  { CAPTURE_IFREMOTE, "Remote..." }
};

#define REMOTE_HOST_START ((sizeof(iftype) / sizeof(iftype[0])) + 1)
#define REMOTE_HOST_SEPARATOR "---"

static void
iftype_combo_box_add_remote_separators (GtkWidget *iftype_cbx)
{
  gtk_combo_box_append_text(GTK_COMBO_BOX(iftype_cbx), REMOTE_HOST_SEPARATOR);
  gtk_combo_box_append_text(GTK_COMBO_BOX(iftype_cbx), REMOTE_HOST_SEPARATOR);
  gtk_combo_box_append_text(GTK_COMBO_BOX(iftype_cbx), "Clear list");
}

static void
iftype_combo_box_add (GtkWidget *iftype_cbx)
{
  GtkTreeModel *model;
  GtkTreeIter iter;
  struct remote_host *rh;
  gboolean create_new = FALSE;
  gchar *string;
  guint i, pos = REMOTE_HOST_START;

  rh = g_hash_table_lookup (remote_host_list, g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_host);
  if (!rh) {
    rh = g_malloc0 (sizeof (*rh));
    if (g_hash_table_size (remote_host_list) == 0) {
      iftype_combo_box_add_remote_separators (iftype_cbx);
    }
    gtk_combo_box_insert_text(GTK_COMBO_BOX(iftype_cbx), pos, g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_host);
    rh->remote_host = g_strdup (g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_host);
    create_new = TRUE;
  } else {
    model = gtk_combo_box_get_model(GTK_COMBO_BOX(iftype_cbx));
    if (gtk_tree_model_get_iter_first(model, &iter)) {
      /* Skip the first entries */
      for (i = 0; i < REMOTE_HOST_START; i++)
        gtk_tree_model_iter_next(model, &iter);
      do {
        gtk_tree_model_get(model, &iter, 0, &string, -1);
        if (string) {
          if (strcmp (g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_host, string) == 0) {
            /* Found match, show this position in combo box */
            g_free (string);
            break;
          }
          g_free (string);
        }
        pos++;
      } while (gtk_tree_model_iter_next(model, &iter));
    }

    g_free (rh->remote_port);
    g_free (rh->auth_username);
    g_free (rh->auth_password);
  }

  rh->remote_port = g_strdup (g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_port);
  rh->auth_type = g_array_index(global_capture_opts.ifaces, interface_options, 0).auth_type;
  rh->auth_username = g_strdup (g_array_index(global_capture_opts.ifaces, interface_options, 0).auth_username);
  rh->auth_password = g_strdup (g_array_index(global_capture_opts.ifaces, interface_options, 0).auth_password);

  if (create_new) {
    g_hash_table_insert (remote_host_list, g_strdup (g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_host), rh);
  }

  g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_VALUE_KEY, GINT_TO_POINTER(pos));
  g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_NOUPDATE_KEY, GINT_TO_POINTER(1));
  gtk_combo_box_set_active(GTK_COMBO_BOX(iftype_cbx), pos);
  g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_NOUPDATE_KEY, GINT_TO_POINTER(0));
}

static void
iftype_combo_box_add_remote_host (gpointer key, gpointer value _U_, gpointer user_data)
{
  gtk_combo_box_insert_text(GTK_COMBO_BOX(user_data), REMOTE_HOST_START, key);

  if (g_array_index(global_capture_opts.ifaces, interface_options, 0).src_type == CAPTURE_IFREMOTE) {
    /* Ensure we select the correct entry */
    if (strcmp ((char *)key, g_array_index(global_capture_opts.ifaces, interface_options, 0).remote_host) == 0) {
      gtk_combo_box_set_active(GTK_COMBO_BOX(user_data), REMOTE_HOST_START);
    }
  }
}

/* Fill the menu of available types of interfaces */
static GtkWidget *
iftype_combo_box_new(void)
{
  GtkWidget *iftype_cbx;
  unsigned int i;

  iftype_cbx = gtk_combo_box_new_text();

  for (i = 0; i < sizeof(iftype) / sizeof(iftype[0]); i++) {
    gtk_combo_box_append_text(GTK_COMBO_BOX(iftype_cbx), iftype[i].name);
  }

  if (g_hash_table_size (remote_host_list) > 0) {
    /* Add remote hosts */
    iftype_combo_box_add_remote_separators (iftype_cbx);
    g_hash_table_foreach (remote_host_list, iftype_combo_box_add_remote_host, iftype_cbx);
  }

  if (g_array_index(global_capture_opts.ifaces, interface_options, 0).src_type == CAPTURE_IFLOCAL) {
    gtk_combo_box_set_active(GTK_COMBO_BOX(iftype_cbx), CAPTURE_IFLOCAL);
  } else {
    int iftype = gtk_combo_box_get_active(GTK_COMBO_BOX(iftype_cbx));
    g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_VALUE_KEY, GINT_TO_POINTER(iftype));
  }
  g_signal_connect(iftype_cbx, "changed", G_CALLBACK(select_if_type_cb), NULL);

  return iftype_cbx;
}

static gboolean
iftype_combo_is_separator (GtkTreeModel *model, GtkTreeIter *iter, gpointer data _U_)
{
  gboolean result = FALSE;
  gchar *string;

  gtk_tree_model_get(model, iter, 0, &string, -1);
  if (string) {
    result = !strcmp (string, REMOTE_HOST_SEPARATOR);
    g_free (string);
  }

  return result;

}

static void
error_list_remote_interface_cb (gpointer dialog _U_, gint btn _U_, gpointer data)
{
  capture_remote_cb(GTK_WIDGET(data), FALSE);
}

/* Retrieve the list of local or remote interfaces according to selected
 * options and re-fill interface name combobox */
static void
update_interface_list(void)
{
  GtkWidget    *if_cb, *iftype_cbx, *remote_bt;
  GList        *if_list, *combo_list, *combo_list_entry;
  GtkTreeModel *model;

  int        iftype, prev_iftype, err;
  gchar     *err_str;

  if (cap_open_w == NULL)
    return;

  if_cb = (GtkWidget *)g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IFACE_KEY);
  iftype_cbx = g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IFTYPE_CBX_KEY);
  remote_bt = g_object_get_data(G_OBJECT(iftype_cbx), E_OPT_REMOTE_BT_KEY);
  iftype = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                             E_CAP_CBX_IFTYPE_VALUE_KEY));

  if_list = (GList *) g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY);
  if (if_list) {
    free_interface_list(if_list);
  }
  if (iftype >= CAPTURE_IFREMOTE) {
    interface_options interface_opts;
    interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
    if_list = get_remote_interface_list(interface_opts.remote_host,
                                        interface_opts.remote_port,
                                        interface_opts.auth_type,
                                        interface_opts.auth_username,
                                        interface_opts.auth_password,
                                        &err, &err_str);
    g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY, if_list);
  } else {
    if_list = capture_interface_list(&err, &err_str);   /* Warning: see capture_prep_cb() */
    g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY, NULL);
  }

  if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
    gpointer dialog = simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
    g_free(err_str);

    if (iftype >= CAPTURE_IFREMOTE) {
      /* Fall back to previous interface list */
      simple_dialog_set_cb(dialog, error_list_remote_interface_cb, iftype_cbx);
      prev_iftype = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                                      E_CAP_CBX_PREV_IFTYPE_VALUE_KEY));
      g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_VALUE_KEY, GINT_TO_POINTER(prev_iftype));
      return;
    }

  } else if (iftype == CAPTURE_IFREMOTE) {
    /* New remote interface */
    iftype_combo_box_add (iftype_cbx);
  }

  /* Empty the interface combo box */
  model = gtk_combo_box_get_model(GTK_COMBO_BOX(if_cb));
  while (gtk_tree_model_iter_n_children(model, NULL) > 0) {
    gtk_combo_box_remove_text (GTK_COMBO_BOX(if_cb), 0);
  }

  combo_list = build_capture_combo_list(if_list, TRUE);
  for (combo_list_entry = combo_list; combo_list_entry != NULL; combo_list_entry = g_list_next(combo_list_entry)) {
      gtk_combo_box_append_text(GTK_COMBO_BOX(if_cb), combo_list_entry->data);
  }

  if (combo_list == NULL)
    gtk_combo_box_append_text(GTK_COMBO_BOX(if_cb), "");

  gtk_combo_box_set_active(GTK_COMBO_BOX(if_cb),0);

  free_capture_combo_list(combo_list);

  if (iftype == CAPTURE_IFLOCAL) {
    /* Only delete if fetched local */
    free_interface_list(if_list);
    gtk_widget_set_sensitive(remote_bt, FALSE);
  } else {
    gtk_widget_set_sensitive(remote_bt, TRUE);
  }
}

/* User changed an interface entry of "Remote interface" dialog */
static void
capture_remote_adjust_sensitivity(GtkWidget *tb _U_, gpointer parent_w)
{
  GtkWidget *auth_passwd_rb,
            *username_lb, *username_te,
            *passwd_lb, *passwd_te;
  gboolean  state;

  auth_passwd_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
                                                  E_REMOTE_AUTH_PASSWD_KEY);
  username_lb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
                                               E_REMOTE_USERNAME_LB_KEY);
  username_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w),
                                               E_REMOTE_USERNAME_TE_KEY);
  passwd_lb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_REMOTE_PASSWD_LB_KEY);
  passwd_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_REMOTE_PASSWD_TE_KEY);

  state =  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auth_passwd_rb));
  gtk_widget_set_sensitive(GTK_WIDGET(username_lb), state);
  gtk_widget_set_sensitive(GTK_WIDGET(username_te), state);
  gtk_widget_set_sensitive(GTK_WIDGET(passwd_lb), state);
  gtk_widget_set_sensitive(GTK_WIDGET(passwd_te), state);
}

/* user requested to destroy the dialog */
static void
capture_remote_destroy_cb(GtkWidget *win, gpointer user_data _U_)
{
  GtkWidget *caller;

  caller = g_object_get_data(G_OBJECT(win), E_CAP_REMOTE_CALLER_PTR_KEY);
  g_object_set_data(G_OBJECT(caller), E_CAP_REMOTE_DIALOG_PTR_KEY, NULL);
}

/* user requested to accept remote interface options */
static void
capture_remote_ok_cb(GtkWidget *win _U_, GtkWidget *remote_w)
{
  GtkWidget *host_te, *port_te, *auth_pwd_rb, *username_te, *passwd_te,
            *auth_null_rb, *auth_passwd_rb, *iftype_cbx;
  int prev_iftype;
  interface_options interface_opts;

  if (remote_w == NULL)
    return;

  host_te = (GtkWidget *)g_object_get_data(G_OBJECT(remote_w), E_REMOTE_HOST_TE_KEY);
  port_te = (GtkWidget *)g_object_get_data(G_OBJECT(remote_w), E_REMOTE_PORT_TE_KEY);
  auth_pwd_rb = (GtkWidget *)g_object_get_data(G_OBJECT(remote_w),
                                               E_REMOTE_AUTH_PASSWD_KEY);
  username_te = (GtkWidget *)g_object_get_data(G_OBJECT(remote_w),
                                               E_REMOTE_USERNAME_TE_KEY);
  passwd_te = (GtkWidget *)g_object_get_data(G_OBJECT(remote_w), E_REMOTE_PASSWD_TE_KEY);
  auth_null_rb = (GtkWidget *) g_object_get_data(G_OBJECT(remote_w), E_REMOTE_AUTH_NULL_KEY);
  auth_passwd_rb = (GtkWidget *) g_object_get_data(G_OBJECT(remote_w), E_REMOTE_AUTH_PASSWD_KEY);
  iftype_cbx = g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IFTYPE_CBX_KEY);
  prev_iftype = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                                  E_CAP_CBX_IFTYPE_VALUE_KEY));

  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
  g_free(interface_opts.remote_host);
  interface_opts.remote_host = g_strdup(gtk_entry_get_text(GTK_ENTRY(host_te)));
  g_free(interface_opts.remote_port);
  interface_opts.remote_port = g_strdup(gtk_entry_get_text(GTK_ENTRY(port_te)));
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auth_passwd_rb)))
    interface_opts.auth_type = CAPTURE_AUTH_PWD;
  else
    interface_opts.auth_type = CAPTURE_AUTH_NULL;

  g_free(interface_opts.auth_username);
  interface_opts.auth_username =
    g_strdup(gtk_entry_get_text(GTK_ENTRY(username_te)));

  g_free(interface_opts.auth_password);
  interface_opts.auth_password =
    g_strdup(gtk_entry_get_text(GTK_ENTRY(passwd_te)));

  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_PREV_IFTYPE_VALUE_KEY,
                    GINT_TO_POINTER(prev_iftype));
  g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_VALUE_KEY,
                    GINT_TO_POINTER(CAPTURE_IFREMOTE));

  window_destroy(GTK_WIDGET(remote_w));
  update_interface_list();
}

static void
capture_remote_cancel_cb(GtkWidget *win, gpointer data)
{
  GtkWidget *iftype_cbx;
  int old_iftype;

  iftype_cbx = g_object_get_data(G_OBJECT(cap_open_w), E_CAP_IFTYPE_CBX_KEY);
  old_iftype = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                                 E_CAP_CBX_PREV_IFTYPE_VALUE_KEY));
  gtk_combo_box_set_active(GTK_COMBO_BOX(iftype_cbx), old_iftype);

  window_cancel_button_cb (win, data);
}

/* Show remote capture interface parameters dialog */
static void
capture_remote_cb(GtkWidget *w, gboolean focus_username)
{
  GtkWidget   *caller, *remote_w,
              *main_vb, *host_tb,
              *host_lb, *host_te, *port_lb, *port_te,
              *auth_fr, *auth_vb,
              *auth_null_rb, *auth_passwd_rb, *auth_passwd_tb,
              *user_lb, *user_te, *passwd_lb, *passwd_te,
              *bbox, *ok_bt, *cancel_bt;
  gchar       *title;
  GSList      *auth_group;
  interface_options interface_opts;

  caller = gtk_widget_get_toplevel(w);
  remote_w = g_object_get_data(G_OBJECT(caller), E_CAP_REMOTE_DIALOG_PTR_KEY);
  if (remote_w != NULL) {
    reactivate_window(remote_w);
    return;
  }

  title = create_user_window_title("Wireshark: Remote Interface");
  remote_w = dlg_window_new(title);
  g_object_set_data(G_OBJECT(remote_w), E_CAP_REMOTE_CALLER_PTR_KEY, caller);
  g_object_set_data(G_OBJECT(caller), E_CAP_REMOTE_DIALOG_PTR_KEY, remote_w);
  g_free(title);

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(remote_w), main_vb);

  /* Host/port table */
  host_tb = gtk_table_new(2, 2, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE(host_tb), 3);
  gtk_table_set_col_spacings(GTK_TABLE(host_tb), 3);
  gtk_box_pack_start(GTK_BOX(main_vb), host_tb, FALSE, FALSE, 0);

  /* Host row */
  host_lb = gtk_label_new("Host:");
  gtk_table_attach_defaults(GTK_TABLE(host_tb), host_lb, 0, 1, 0, 1);

  host_te = gtk_entry_new();
  gtk_widget_set_tooltip_text(host_te,  "Enter the hostname or host IP address to be used as a source for remote capture.");
  gtk_table_attach_defaults(GTK_TABLE(host_tb), host_te, 1, 2, 0, 1);
  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  if (interface_opts.remote_host != NULL)
    gtk_entry_set_text(GTK_ENTRY(host_te), interface_opts.remote_host);

  /* Port row */
  port_lb = gtk_label_new("Port:");
  gtk_table_attach_defaults(GTK_TABLE(host_tb), port_lb, 0, 1, 1, 2);

  port_te = gtk_entry_new();
  gtk_widget_set_tooltip_text(port_te, "Enter the TCP port number used by RPCAP server at remote host "
                              "(leave it empty for default port number).");
  gtk_table_attach_defaults(GTK_TABLE(host_tb), port_te, 1, 2, 1, 2);
  if (interface_opts.remote_port != NULL)
    gtk_entry_set_text(GTK_ENTRY(port_te), interface_opts.remote_port);

  /* Authentication options frame */
  auth_fr = gtk_frame_new("Authentication");
  gtk_container_add(GTK_CONTAINER(main_vb), auth_fr);

  auth_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(auth_vb), 5);
  gtk_container_add(GTK_CONTAINER(auth_fr), auth_vb);

  auth_null_rb = gtk_radio_button_new_with_label(NULL,
                                                 "Null authentication");
  gtk_box_pack_start(GTK_BOX(auth_vb), auth_null_rb, TRUE, TRUE, 0);

  auth_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(auth_null_rb));
  auth_passwd_rb = gtk_radio_button_new_with_label(auth_group,
                                                   "Password authentication");
  gtk_box_pack_start(GTK_BOX(auth_vb), auth_passwd_rb, TRUE, TRUE, 0);
  g_signal_connect(auth_passwd_rb, "toggled",
                   G_CALLBACK(capture_remote_adjust_sensitivity), remote_w);

  auth_passwd_tb = gtk_table_new(2, 2, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE(auth_passwd_tb), 3);
  gtk_table_set_col_spacings(GTK_TABLE(auth_passwd_tb), 3);
  gtk_box_pack_start(GTK_BOX(auth_vb), auth_passwd_tb, FALSE, FALSE, 0);

  user_lb = gtk_label_new("Username:");
  gtk_table_attach_defaults(GTK_TABLE(auth_passwd_tb), user_lb, 0, 1, 0, 1);

  user_te = gtk_entry_new();
  gtk_table_attach_defaults(GTK_TABLE(auth_passwd_tb), user_te, 1, 2, 0, 1);
  if (interface_opts.auth_username != NULL)
    gtk_entry_set_text(GTK_ENTRY(user_te), interface_opts.auth_username);

  passwd_lb = gtk_label_new("Password:");
  gtk_table_attach_defaults(GTK_TABLE(auth_passwd_tb), passwd_lb, 0, 1, 1, 2);

  passwd_te = gtk_entry_new();
  gtk_entry_set_visibility(GTK_ENTRY(passwd_te), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(auth_passwd_tb), passwd_te, 1, 2, 1, 2);
  if (interface_opts.auth_password != NULL)
    gtk_entry_set_text(GTK_ENTRY(passwd_te), interface_opts.auth_password);

  /* Button row: "Start" and "Cancel" buttons */
  bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(capture_remote_ok_cb), remote_w);
  gtk_widget_set_tooltip_text(ok_bt,
                       "Accept remote host parameters and lookup "
                       "remote interfaces.");

  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  gtk_widget_set_tooltip_text(cancel_bt, "Cancel and exit dialog.");
  window_set_cancel_button(remote_w, cancel_bt, capture_remote_cancel_cb);

  if (focus_username) {
    /* Give the initial focus to the "Username" entry box. */
    gtk_widget_grab_focus(user_te);
  }

  gtk_widget_grab_default(ok_bt);

  /* Catch the "activate" signal on the text
     entries, so that if the user types Return there, we act as if the
     "OK" button had been selected, as happens if Return is typed if some
     widget that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(host_te, ok_bt);
  dlg_set_activate(port_te, ok_bt);
  dlg_set_activate(user_te, ok_bt);
  dlg_set_activate(passwd_te, ok_bt);

  g_signal_connect(remote_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(remote_w, "destroy", G_CALLBACK(capture_remote_destroy_cb), NULL);

  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_HOST_TE_KEY, host_te);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_PORT_TE_KEY, port_te);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_AUTH_NULL_KEY, auth_null_rb);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_AUTH_PASSWD_KEY, auth_passwd_rb);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_USERNAME_LB_KEY, user_lb);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_USERNAME_TE_KEY, user_te);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_PASSWD_LB_KEY, passwd_lb);
  g_object_set_data(G_OBJECT(remote_w), E_REMOTE_PASSWD_TE_KEY, passwd_te);

  if (interface_opts.auth_type == CAPTURE_AUTH_PWD)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(auth_passwd_rb), TRUE);
  else
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(auth_null_rb), TRUE);
  capture_remote_adjust_sensitivity(NULL, remote_w);

  gtk_widget_show_all(remote_w);
  window_present(remote_w);
}

/* user requested to destroy the dialog */
static void
options_remote_destroy_cb(GtkWidget *win, gpointer user_data _U_)
{
  GtkWidget *caller;

  caller = g_object_get_data(G_OBJECT(win), E_OPT_REMOTE_CALLER_PTR_KEY);
  g_object_set_data(G_OBJECT(caller), E_OPT_REMOTE_DIALOG_PTR_KEY, NULL);
}

/* user requested to accept remote interface options */
static void
options_remote_ok_cb(GtkWidget *win _U_, GtkWidget *parent_w)
{
  GtkWidget *datatx_udp_cb, *nocap_rpcap_cb;
#ifdef HAVE_PCAP_SETSAMPLING
  GtkWidget *samp_none_rb, *samp_count_rb, *samp_timer_rb,
            *samp_count_sb, *samp_timer_sb;
#endif
  interface_options interface_opts;

  if (parent_w == NULL)
    return;

  datatx_udp_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_DATATX_UDP_CB_KEY);
  nocap_rpcap_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_NOCAP_RPCAP_CB_KEY);

  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
  interface_opts.datatx_udp =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(datatx_udp_cb));
  interface_opts.nocap_rpcap =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(nocap_rpcap_cb));

#ifdef HAVE_PCAP_SETSAMPLING
  samp_none_rb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_NONE_RB_KEY);
  samp_count_rb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_COUNT_RB_KEY);
  samp_timer_rb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_TIMER_RB_KEY);
  samp_count_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_COUNT_SB_KEY);
  samp_timer_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_TIMER_SB_KEY);

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(samp_none_rb)))
    interface_opts.sampling_method = CAPTURE_SAMP_NONE;
  else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(samp_count_rb))) {
    interface_opts.sampling_method = CAPTURE_SAMP_BY_COUNT;
    interface_opts.sampling_param = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(samp_count_sb));
  } else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(samp_timer_rb))) {
    interface_opts.sampling_method = CAPTURE_SAMP_BY_TIMER;
    interface_opts.sampling_param = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(samp_timer_sb));
  }
#endif

  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  window_destroy(GTK_WIDGET(parent_w));
}

#ifdef HAVE_PCAP_SETSAMPLING
static void
options_prep_adjust_sensitivity(GtkWidget *tb _U_, gpointer parent_w)
{
  GtkWidget *samp_count_rb, *samp_timer_rb,
            *samp_count_sb, *samp_timer_sb;

  samp_count_rb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_COUNT_RB_KEY);
  samp_timer_rb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_TIMER_RB_KEY);
  samp_count_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_COUNT_SB_KEY);
  samp_timer_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SAMP_TIMER_SB_KEY);

  if (samp_count_sb && samp_count_rb)
   gtk_widget_set_sensitive(GTK_WIDGET(samp_count_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(samp_count_rb)));

  if (samp_timer_sb && samp_timer_rb)
   gtk_widget_set_sensitive(GTK_WIDGET(samp_timer_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(samp_timer_rb)));
}
#endif

void
options_remote_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget *opt_remote_w, *main_vb;
  GtkWidget   *caller, *bbox, *ok_bt, *cancel_bt;
  GtkWidget     *capture_fr, *capture_vb;
  GtkWidget     *nocap_rpcap_cb, *datatx_udp_cb;
#ifdef HAVE_PCAP_SETSAMPLING
  GtkWidget     *sampling_fr, *sampling_vb, *sampling_tb, *sampling_lb,
                *samp_none_rb, *samp_count_rb, *samp_timer_rb,
                *samp_count_sb, *samp_timer_sb;
  GtkAdjustment *samp_count_adj, *samp_timer_adj;
  GSList        *samp_group;
#endif
  interface_options interface_opts;

  caller = gtk_widget_get_toplevel(w);
  opt_remote_w = g_object_get_data(G_OBJECT(caller), E_OPT_REMOTE_DIALOG_PTR_KEY);
  if (opt_remote_w != NULL) {
    reactivate_window(opt_remote_w);
    return;
  }

  opt_remote_w = dlg_window_new("Remote Capture Settings");
  g_object_set_data(G_OBJECT(opt_remote_w), E_OPT_REMOTE_CALLER_PTR_KEY, caller);
  g_object_set_data(G_OBJECT(caller), E_OPT_REMOTE_DIALOG_PTR_KEY, opt_remote_w);

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(opt_remote_w), main_vb);

  /* Remote capture options */
  capture_fr = gtk_frame_new("Capture Options");
  gtk_container_add(GTK_CONTAINER(main_vb), capture_fr);

  capture_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(capture_vb), 5);
  gtk_container_add(GTK_CONTAINER(capture_fr), capture_vb);

  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  nocap_rpcap_cb = gtk_check_button_new_with_mnemonic("Do not capture own RPCAP traffic");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(nocap_rpcap_cb),
          interface_opts.nocap_rpcap);
  gtk_container_add(GTK_CONTAINER(capture_vb), nocap_rpcap_cb);

  datatx_udp_cb = gtk_check_button_new_with_mnemonic("Use UDP for data transfer");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(datatx_udp_cb),
          interface_opts.datatx_udp);
  gtk_container_add(GTK_CONTAINER(capture_vb), datatx_udp_cb);

#ifdef HAVE_PCAP_SETSAMPLING
  /* Sampling options */
  sampling_fr = gtk_frame_new("Sampling Options");
  gtk_container_add(GTK_CONTAINER(main_vb), sampling_fr);

  sampling_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(sampling_vb), 5);
  gtk_container_add(GTK_CONTAINER(sampling_fr), sampling_vb);

  sampling_tb = gtk_table_new(3, 3, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE(sampling_tb), 1);
  gtk_table_set_col_spacings(GTK_TABLE(sampling_tb), 3);
  gtk_box_pack_start(GTK_BOX(sampling_vb), sampling_tb, FALSE, FALSE, 0);

  /* "No sampling" row */
  samp_none_rb = gtk_radio_button_new_with_label(NULL, "None");
  if (interface_opts.sampling_method == CAPTURE_SAMP_NONE)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(samp_none_rb), TRUE);
  g_signal_connect(samp_none_rb, "toggled",
                 G_CALLBACK(options_prep_adjust_sensitivity), opt_remote_w);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), samp_none_rb, 0, 1, 0, 1);

  /* "Sampling by counter" row */
  samp_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(samp_none_rb));
  samp_count_rb = gtk_radio_button_new_with_label(samp_group, "1 of");
  if (interface_opts.sampling_method == CAPTURE_SAMP_BY_COUNT)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(samp_count_rb), TRUE);
  g_signal_connect(samp_count_rb, "toggled",
                 G_CALLBACK(options_prep_adjust_sensitivity), opt_remote_w);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), samp_count_rb, 0, 1, 1, 2);

  samp_count_adj = (GtkAdjustment *) gtk_adjustment_new(
                        (gfloat)interface_opts.sampling_param,
                        1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  samp_count_sb = gtk_spin_button_new(samp_count_adj, 0, 0);
  gtk_spin_button_set_wrap(GTK_SPIN_BUTTON(samp_count_sb), TRUE);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), samp_count_sb, 1, 2, 1, 2);

  sampling_lb = gtk_label_new("packets");
  gtk_misc_set_alignment(GTK_MISC(sampling_lb), 0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), sampling_lb, 2, 3, 1, 2);

  /* "Sampling by timer" row */
  samp_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(samp_count_rb));
  samp_timer_rb = gtk_radio_button_new_with_label(samp_group, "1 every");
  if (interface_opts.sampling_method == CAPTURE_SAMP_BY_TIMER)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(samp_timer_rb), TRUE);
  g_signal_connect(samp_timer_rb, "toggled",
                 G_CALLBACK(options_prep_adjust_sensitivity), opt_remote_w);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), samp_timer_rb, 0, 1, 2, 3);

  samp_timer_adj = (GtkAdjustment *) gtk_adjustment_new(
                        (gfloat)interface_opts.sampling_param,
                        1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  samp_timer_sb = gtk_spin_button_new(samp_timer_adj, 0, 0);
  gtk_spin_button_set_wrap(GTK_SPIN_BUTTON(samp_timer_sb), TRUE);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), samp_timer_sb, 1, 2, 2, 3);

  sampling_lb = gtk_label_new("milliseconds");
  gtk_misc_set_alignment(GTK_MISC(sampling_lb), 0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(sampling_tb), sampling_lb, 2, 3, 2, 3);
#endif

  /* Button row: "Start" and "Cancel" buttons */
  bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(options_remote_ok_cb), opt_remote_w);
  gtk_widget_set_tooltip_text(ok_bt, "Accept parameters and close dialog");
  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  gtk_widget_set_tooltip_text(cancel_bt, "Cancel and exit dialog.");
  window_set_cancel_button(opt_remote_w, cancel_bt, window_cancel_button_cb);

  gtk_widget_grab_default(ok_bt);

  g_signal_connect(opt_remote_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(opt_remote_w, "destroy", G_CALLBACK(options_remote_destroy_cb), NULL);

  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_NOCAP_RPCAP_CB_KEY, nocap_rpcap_cb);
  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_DATATX_UDP_CB_KEY, datatx_udp_cb);

#ifdef HAVE_PCAP_SETSAMPLING
  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_SAMP_NONE_RB_KEY, samp_none_rb);
  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_SAMP_COUNT_RB_KEY, samp_count_rb);
  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_SAMP_COUNT_SB_KEY, samp_count_sb);
  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_SAMP_TIMER_RB_KEY, samp_timer_rb);
  g_object_set_data(G_OBJECT(opt_remote_w), E_CAP_SAMP_TIMER_SB_KEY, samp_timer_sb);
#endif

#ifdef HAVE_PCAP_SETSAMPLING
  /* Set the sensitivity of various widgets as per the settings of other
     widgets. */
  options_prep_adjust_sensitivity(NULL, opt_remote_w);
#endif

  gtk_widget_show_all(opt_remote_w);
  window_present(opt_remote_w);
}

static void
recent_print_remote_host (gpointer key _U_, gpointer value, gpointer user)
{
  FILE *rf = user;
  struct remote_host *ri = value;

  fprintf (rf, RECENT_KEY_REMOTE_HOST ": %s,%s,%d\n", ri->remote_host, ri->remote_port, ri->auth_type);
}

void
capture_remote_combo_recent_write_all(FILE *rf)
{
  if (remote_host_list && g_hash_table_size (remote_host_list) > 0) {
    /* Write all remote interfaces to the recent file */
    g_hash_table_foreach (remote_host_list, recent_print_remote_host, rf);
  }
}

gboolean
capture_remote_combo_add_recent(gchar *s)
{
  GList *vals = prefs_get_string_list (s);
  GList *valp = vals;
  struct remote_host *rh;
  gint auth_type;
  char *p;

  if (valp == NULL)
    return FALSE;

  if (remote_host_list == NULL) {
    remote_host_list = g_hash_table_new (g_str_hash, g_str_equal);
  }

  rh = g_malloc (sizeof (*rh));

  /* First value is the host */
  rh->remote_host = g_strdup (valp->data);
  if (strlen(rh->remote_host) == 0)
    /* Empty remote host */
    return FALSE;
  rh->auth_type = CAPTURE_AUTH_NULL;
  valp = valp->next;

  if (valp) {
    /* Found value 2, this is the port number */
    rh->remote_port = g_strdup (valp->data);
    valp = valp->next;
  } else {
    /* Did not find a port number */
    rh->remote_port = g_strdup ("");
  }

  if (valp) {
    /* Found value 3, this is the authentication type */
    auth_type = strtol(valp->data, &p, 0);
    if (p != valp->data && *p == '\0') {
      rh->auth_type = auth_type;
    }
  }

  /* Do not store username and password */
  rh->auth_username = g_strdup ("");
  rh->auth_password = g_strdup ("");

  prefs_clear_string_list(vals);

  g_hash_table_insert (remote_host_list, g_strdup(rh->remote_host), rh);

  return TRUE;
}

#endif

#if defined(HAVE_PCAP_OPEN_DEAD) && defined(HAVE_BPF_IMAGE)
static void
capture_filter_compile_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
  pcap_t *pd;
  struct bpf_program fcode;

  GtkWidget *filter_cm;
  const gchar *filter_text;

  pd = pcap_open_dead(g_array_index(global_capture_opts.ifaces, interface_options, 0).linktype, DUMMY_SNAPLENGTH);

  filter_cm = g_object_get_data(G_OBJECT(top_level), E_CFILTER_CM_KEY);
#if GTK_CHECK_VERSION(2,24,0)
  filter_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(filter_cm));
#else
  filter_text = gtk_combo_box_get_active_text (GTK_COMBO_BOX(filter_cm));
#endif /* GTK_CHECK_VERSION(2,24,0) */
  /* pcap_compile will not alter the filter string, so the (char *) cast is "safe" */
#ifdef PCAP_NETMASK_UNKNOWN
  if (pcap_compile(pd, &fcode, (char *)filter_text, 1 /* Do optimize */, PCAP_NETMASK_UNKNOWN) < 0) {
#else
  if (pcap_compile(pd, &fcode, (char *)filter_text, 1 /* Do optimize */, 0) < 0) {
#endif
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", pcap_geterr(pd));
  } else {
    GString *bpf_code_dump = g_string_new("");
    struct bpf_insn *insn = fcode.bf_insns;
    int i, n = fcode.bf_len;

    gchar *bpf_code_str;
    gchar *bpf_code_markup;

    for (i = 0; i < n; ++insn, ++i) {
        g_string_append(bpf_code_dump, bpf_image(insn, i));
        g_string_append(bpf_code_dump, "\n");
    }

    bpf_code_str = g_string_free(bpf_code_dump, FALSE);
    bpf_code_markup = g_markup_escape_text(bpf_code_str, -1);

    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "<markup><tt>%s</tt></markup>", bpf_code_markup);

    g_free(bpf_code_str);
    g_free(bpf_code_markup);
  }

  pcap_close(pd);
}
#endif

/* show capture prepare (options) dialog */

/* XXX: Warning:
        Note that capture_interface_list() is called directly (or indirectly) during the
         creation of (and changes to) the capture options dialog window.

        Also note that capture_interface_list() indirectly runs the gtk main loop temporarily
         to process queued events (which may include button-presses, key-presses, etc).
         (This is done while awaiting a response from dumpcap which is invoked to obtain
          the capture interface list).
        This means other Wireshark callbacks can be invoked while the capture options window
         is being created or updated (in effect an "interrupt" can occur).

        Needless to say, "race conditions" may occur in "interrupt" code which depends upon the exact
        state of the capture options dialog window and which may be invoked during the
        creation of (or changes to) the capture options dialog window.

        For example: if a user hits "Capture:Options" and then immediately hits "Capture:Start",
         capture_start_cb() may be invoked before capture_prep_cb() has been completed (i.e., during
         a call to capture_interface_list() in the code which creates the capture options window).
        capture_start_cb() depends upon certain properties of the capture options window having been
         initialized and thus fails if the properties have not (yet) been initialized.

        An interlock has been added to handle this particular situation;
        Ideally a more general solution should be implemented since it's probably difficult
         (if not nearly impossible) to identify all the possible "race conditions".

        ? Prevent the temporary running of the gtk main loop in cases wherein dumpcap is invoked for a
          simple request/reply ? (e.g., capture_interface_list()) ??

        ? Other ??
*/

void
capture_prep_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *main_vb,
                *main_hb, *left_vb, *right_vb,

                *capture_fr, *capture_vb,
                *if_hb, *if_cb, *if_lb,
                *if_ip_hb, *if_ip_lb, *if_ip_eb,
                *linktype_hb, *linktype_lb, *linktype_combo_box,
                *snap_hb, *snap_cb, *snap_sb, *snap_lb,
                *promisc_cb,
#ifdef HAVE_PCAP_CREATE
                *monitor_cb,
#endif
                *pcap_ng_cb,
                *filter_hb, *filter_bt, *filter_te, *filter_cm,
#if defined(HAVE_PCAP_OPEN_DEAD) && defined(HAVE_BPF_IMAGE)
                *compile_bt,
#endif
                *file_fr, *file_vb,
                *file_hb, *file_bt, *file_lb, *file_te,
                *multi_tb, *multi_files_on_cb,
                *ring_filesize_cb, *ring_filesize_sb, *ring_filesize_cbx,
                *file_duration_cb, *file_duration_sb, *file_duration_cbx,
                *ringbuffer_nbf_cb, *ringbuffer_nbf_sb, *ringbuffer_nbf_lb,
                *stop_files_cb, *stop_files_sb, *stop_files_lb,

                *limit_fr, *limit_vb, *limit_tb,
                *stop_packets_cb, *stop_packets_sb, *stop_packets_lb,
                *stop_filesize_cb, *stop_filesize_sb, *stop_filesize_cbx,
                *stop_duration_cb, *stop_duration_sb, *stop_duration_cbx,

                *display_fr, *display_vb,
                *sync_cb, *auto_scroll_cb, *hide_info_cb,

                *resolv_fr, *resolv_vb,
                *m_resolv_cb, *n_resolv_cb, *t_resolv_cb,
                *bbox, *ok_bt, *cancel_bt,
                *help_bt;
                GList *cf_entry;
                GList *combo_list_entry;
#ifdef HAVE_AIRPCAP
  GtkWidget     *advanced_bt;
  GtkWidget     *decryption_cb;
#endif
#ifdef HAVE_PCAP_REMOTE
  GtkWidget     *iftype_cbx;
  GtkWidget     *remote_bt;
#endif
  GtkAdjustment *snap_adj, *ringbuffer_nbf_adj,
                *stop_packets_adj, *stop_filesize_adj, *stop_duration_adj, *stop_files_adj,
                *ring_filesize_adj, *file_duration_adj;
  GList         *if_list, *combo_list, *cfilter_list, *if_entry;
  int           row;
  int           err;
  gchar         *err_str;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  GtkAdjustment *buffer_size_adj;
  GtkWidget     *buffer_size_lb, *buffer_size_sb, *buffer_size_hb;
#endif
  guint32       value;
  gchar         *cap_title;
  gchar         *if_device = NULL;
  if_info_t     *if_info;
  int           if_index = 0;
  interface_options interface_opts;

  if (cap_open_w != NULL) {
    /* There's already a "Capture Options" dialog box; reactivate it. */
    reactivate_window(cap_open_w);
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

  /* use user-defined title if preference is set */
  cap_title = create_user_window_title("Wireshark: Capture Options");

  cap_open_complete = FALSE;
  cap_open_w = dlg_window_new(cap_title);
  g_free(cap_title);

  while (global_capture_opts.ifaces->len > 0) {
    interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
    global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
    g_free(interface_opts.name);
    g_free(interface_opts.descr);
    g_free(interface_opts.cfilter);
#ifdef HAVE_PCAP_REMOTE
    g_free(interface_opts.remote_host);
    g_free(interface_opts.remote_port);
    g_free(interface_opts.auth_username);
    g_free(interface_opts.auth_password);
#endif
  }

  interface_opts.name = NULL;
  interface_opts.descr = NULL;
  interface_opts.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
  interface_opts.snaplen = global_capture_opts.default_options.snaplen;
  interface_opts.has_snaplen = global_capture_opts.default_options.has_snaplen;
  interface_opts.linktype = global_capture_opts.default_options.linktype;
  interface_opts.promisc_mode = global_capture_opts.default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  interface_opts.buffer_size = global_capture_opts.default_options.buffer_size;
#endif
  interface_opts.monitor_mode = global_capture_opts.default_options.monitor_mode;
#ifdef HAVE_PCAP_REMOTE
  interface_opts.src_type = global_capture_opts.default_options.src_type;
  interface_opts.remote_host = g_strdup(global_capture_opts.default_options.remote_host);
  interface_opts.remote_port = g_strdup(global_capture_opts.default_options.remote_port);
  interface_opts.auth_type = global_capture_opts.default_options.auth_type;
  interface_opts.auth_username = g_strdup(global_capture_opts.default_options.auth_username);
  interface_opts.auth_password = g_strdup(global_capture_opts.default_options.auth_password);
  interface_opts.datatx_udp = global_capture_opts.default_options.datatx_udp;
  interface_opts.nocap_rpcap = global_capture_opts.default_options.nocap_rpcap;
  interface_opts.nocap_local = global_capture_opts.default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
  interface_opts.sampling_method = global_capture_opts.default_options.sampling_method;
  interface_opts.sampling_param  = global_capture_opts.default_options.sampling_param;
#endif
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);

#ifdef HAVE_PCAP_REMOTE
  if (interface_opts.src_type == CAPTURE_IFREMOTE) {
    if_list = get_remote_interface_list(interface_opts.remote_host,
                                        interface_opts.remote_port,
                                        interface_opts.auth_type,
                                        interface_opts.auth_username,
                                        interface_opts.auth_password,
                                        &err, NULL);
    if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
      /* Silently fall back to local interface list */
      if (interface_opts.name) {
        g_free (interface_opts.name);
        interface_opts.name = NULL;
      }
      if (interface_opts.descr) {
        g_free (interface_opts.descr);
        interface_opts.descr = NULL;
      }
      if_list = capture_interface_list(&err, &err_str);   /* Warning: see capture_prep_cb() */
      interface_opts.src_type = CAPTURE_IFLOCAL;
      g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY, NULL);
    } else {
      g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY, if_list);
    }
  } else {
    if_list = capture_interface_list(&err, &err_str);   /* Warning: see capture_prep_cb() */
    g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IF_LIST_KEY, NULL);
  }
#else
  if_list = capture_interface_list(&err, &err_str);   /* Warning: see capture_prep_cb() */
#endif
  if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
    g_free(err_str);
  }

#ifdef HAVE_AIRPCAP
  /* update airpcap interface list */

  /* load the airpcap interfaces */
  airpcap_if_list = get_airpcap_interface_list(&err, &err_str);

  decryption_cb = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY);
  update_decryption_mode_list(decryption_cb);

  if (airpcap_if_list == NULL && err == CANT_GET_AIRPCAP_INTERFACE_LIST) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
    g_free(err_str);
  }

  /* select the first as default (THIS SHOULD BE CHANGED) */
  airpcap_if_active = airpcap_get_default_if(airpcap_if_list);
#endif

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_open_w), main_vb);

  /* Capture-related options frame */
  capture_fr = gtk_frame_new("Capture");
  gtk_container_add(GTK_CONTAINER(main_vb), capture_fr);

  capture_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(capture_vb), 5);
  gtk_container_add(GTK_CONTAINER(capture_fr), capture_vb);

  /* Interface row */
  if_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), if_hb);

  if_lb = gtk_label_new("Interface:");
  gtk_box_pack_start(GTK_BOX(if_hb), if_lb, FALSE, FALSE, 3);

#ifdef HAVE_PCAP_REMOTE
  if (remote_host_list == NULL) {
    remote_host_list = g_hash_table_new (g_str_hash, g_str_equal);
  }

  iftype_cbx = iftype_combo_box_new();
  gtk_combo_box_set_row_separator_func (GTK_COMBO_BOX (iftype_cbx),
                                        iftype_combo_is_separator, NULL, NULL);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IFTYPE_CBX_KEY, iftype_cbx);
  gtk_widget_set_tooltip_text(iftype_cbx, "Choose to capture from local or remote interfaces.");
  gtk_box_pack_start(GTK_BOX(if_hb), iftype_cbx, FALSE, FALSE, 0);
#endif

  if (interface_opts.name == NULL && prefs.capture_device != NULL) {
    /* No interface was specified on the command line or in a previous
       capture, but there is one specified in the preferences file;
       make the one from the preferences file the default */
    if_device = g_strdup(prefs.capture_device);
    for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
      if_info = (if_info_t*)if_entry->data;
      if (strcmp(if_info->name, get_if_name(if_device)) == 0) {
        interface_opts.name = g_strdup(get_if_name(if_device));
        /* Warning: see capture_prep_cb() */
        /* XXX: Could the following code be changed to use the if_list obtained above instead  */
        /*      of maybe calling capture_interface_list() again ?                           */
        interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
        break;
      }
    }
    g_free(if_device);
    if_device = NULL;
  }

  /* If we have a prefered interface, get the string to compare with to select the active text*/
  if (interface_opts.name != NULL) {
      if_device = build_capture_combo_name(if_list, interface_opts.name);
  }
#if GTK_CHECK_VERSION(2,24,0)
  if_cb = gtk_combo_box_text_new_with_entry();
  combo_list = build_capture_combo_list(if_list, TRUE);
  if (combo_list != NULL){
    for (combo_list_entry = combo_list; combo_list_entry != NULL; combo_list_entry = g_list_next(combo_list_entry)) {
      gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(if_cb), combo_list_entry->data);
      /* Do we have a prefered if(if_device != NULL),
       * if we do compare to the entry we are making
       * and make that entry active if they are equal.
       */
#else
  if_cb = gtk_combo_box_entry_new_text();
  combo_list = build_capture_combo_list(if_list, TRUE);
  if (combo_list != NULL){
    for (combo_list_entry = combo_list; combo_list_entry != NULL; combo_list_entry = g_list_next(combo_list_entry)) {
      gtk_combo_box_append_text(GTK_COMBO_BOX(if_cb), combo_list_entry->data);
      /* Do we have a prefered if(if_device != NULL),
       * if we do compare to the entry we are making
       * and make that entry active if they are equal.
       */
#endif /* GTK_CHECK_VERSION(2,24,0) */
      if((if_device)&&(strcmp(if_device, combo_list_entry->data) == 0)) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(if_cb),if_index);
      }
      if_index++;
    }
    if(!if_device)
      /* If we did not have an prefered interface make the first one active */
      gtk_combo_box_set_active(GTK_COMBO_BOX(if_cb),0);
  }

  /* If we allocated the string free it */
  g_free(if_device);

  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_IFACE_KEY, if_cb);

#ifdef HAVE_AIRPCAP
  /* get the airpcap interface (if it IS an airpcap interface, and update the
     toolbar... and of course enable the advanced button...)*/
  airpcap_if_selected = get_airpcap_if_from_name(airpcap_if_list,interface_opts.name);
#endif

  free_capture_combo_list(combo_list);
#ifdef HAVE_PCAP_REMOTE
  /* Only delete if fetched local */
  if (interface_opts.src_type == CAPTURE_IFLOCAL)
#endif
  free_interface_list(if_list);
  gtk_widget_set_tooltip_text(if_cb,
"Choose which interface (network adapter) will be used to capture packets from. Be sure to select the correct one, as it's a common mistake to select the wrong interface.");
  gtk_box_pack_start(GTK_BOX(if_hb), if_cb, TRUE, TRUE, 3);

  if_ip_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(capture_vb), if_ip_hb, FALSE, FALSE, 0);

  if_ip_eb = gtk_event_box_new();
  gtk_event_box_set_visible_window (GTK_EVENT_BOX(if_ip_eb), FALSE);
  gtk_box_pack_start(GTK_BOX(if_ip_hb), if_ip_eb, TRUE, TRUE, 3);
  gtk_widget_set_tooltip_text(if_ip_eb, "Lists the IP address(es) "
                       "assigned to the selected interface.  If there are "
                       "more addresses than will fit in the window, the "
                       "first few and the last few will be shown with \"...\" "
                       "between them.");

  if_ip_lb = gtk_label_new("");
  gtk_misc_set_alignment(GTK_MISC(if_ip_lb), 0, 0); /* Left justified */
  gtk_container_add(GTK_CONTAINER(if_ip_eb), if_ip_lb);

  main_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(main_hb), 0);
  gtk_container_add(GTK_CONTAINER(capture_vb), main_hb);

  left_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(left_vb), 0);
  gtk_box_pack_start(GTK_BOX(main_hb), left_vb, TRUE, TRUE, 0);

#if defined (HAVE_AIRPCAP) || defined (HAVE_PCAP_REMOTE) || defined (HAVE_PCAP_CREATE)
  /* Avoid adding the right vbox if not needed, because it steals 3 pixels */
  right_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(right_vb), 0);
  gtk_box_pack_start(GTK_BOX(main_hb), right_vb, FALSE, FALSE, 3);
#endif

  /* Linktype row */
  linktype_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(left_vb), linktype_hb, FALSE, FALSE, 0);

  linktype_lb = gtk_label_new("Link-layer header type:");
  gtk_box_pack_start(GTK_BOX(linktype_hb), linktype_lb, FALSE, FALSE, 3);

  linktype_combo_box = ws_combo_box_new_text_and_pointer();
  g_object_set_data(G_OBJECT(linktype_combo_box), E_CAP_LT_CBX_LABEL_KEY, linktype_lb);
  /* Default to "use the default" */
  /* Datalink menu index is not reset; it will be restored with last used value */
  /* g_object_set_data(G_OBJECT(linktype_combo_box), E_CAP_CBX_LT_VALUE_KEY, GINT_TO_POINTER(-1)); */

  g_object_set_data(G_OBJECT(linktype_combo_box), E_CAP_IFACE_IP_KEY, if_ip_lb);
  if (cap_settings_history == NULL) {
    cap_settings_history = g_hash_table_new(g_str_hash, g_str_equal);
  }
  /*
   * XXX - in some cases, this is "multiple link-layer header types", e.g.
   * some 802.11 interfaces on FreeBSD 5.2 and later, where you can request
   * fake Ethernet, 802.11, or 802.11-plus-radio-information headers.
   *
   * In other cases, it's "multiple link-layer types", e.g., with recent
   * versions of libpcap, a DAG card on an "HDLC" WAN, where you can
   * request Cisco HDLC or PPP depending on what type of traffic is going
   * over the WAN, or an Ethernet interface, where you can request Ethernet
   * or DOCSIS, the latter being for some Cisco cable modem equipment that
   * can be configured to send raw DOCSIS frames over an Ethernet inside
   * Ethernet low-level framing, for traffic capture purposes.
   *
   * We leave it as "multiple link-layer types" for now.
   */
  gtk_widget_set_tooltip_text(linktype_combo_box, "The selected interface supports multiple link-layer types; select the desired one.");
  gtk_box_pack_start (GTK_BOX(linktype_hb), linktype_combo_box, FALSE, FALSE, 0);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_LT_CBX_KEY, linktype_combo_box);
  g_signal_connect(GTK_COMBO_BOX(if_cb), "changed",
                   G_CALLBACK(capture_prep_interface_changed_cb), NULL);

  /* Promiscuous mode row */
  promisc_cb = gtk_check_button_new_with_mnemonic(
      "Capture packets in _promiscuous mode");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(promisc_cb),
                               interface_opts.promisc_mode);
  gtk_widget_set_tooltip_text(promisc_cb,
    "Usually a network adapter will only capture the traffic sent to its own network address. "
    "If you want to capture all traffic that the network adapter can \"see\", mark this option. "
    "See the FAQ for some more details of capturing packets from a switched network.");
  gtk_container_add(GTK_CONTAINER(left_vb), promisc_cb);

#ifdef HAVE_PCAP_CREATE
  /* Monitor mode row */
  monitor_cb = gtk_check_button_new_with_mnemonic(
      "Capture packets in monitor mode");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(monitor_cb),
                               interface_opts.monitor_mode);
  g_signal_connect(monitor_cb, "toggled",
                   G_CALLBACK(capture_prep_monitor_changed_cb), NULL);

  gtk_widget_set_tooltip_text(monitor_cb,
    "Usually a Wi-Fi adapter will, even in promiscuous mode, only capture the traffic on the BSS to which it's associated. "
    "If you want to capture all traffic that the Wi-Fi adapter can \"receive\", mark this option. "
    "In order to see IEEE 802.11 headers or to see radio information for captured packets,"
    "it might be necessary to turn this option on.\n\n"
    "Note that, in monitor mode, the adapter might disassociate from the network to which it's associated.");
  gtk_container_add(GTK_CONTAINER(left_vb), monitor_cb);

  /*
   * Attach this now, so that set_if_capabilities() can change its
   * sensitivity.
   */
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_MONITOR_KEY, monitor_cb);
#endif

  /*
   * This controls the sensitivity of both the link-type list and, if
   * you have it, the monitor mode checkbox.  That's why we do this
   * now.
   */
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
  /* To keep consistency, the status has to be stored */
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  set_if_capabilities(FALSE);

  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  /* Pcap-NG row */
  pcap_ng_cb = gtk_check_button_new_with_mnemonic("Capture packets in pcap-ng format");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(pcap_ng_cb), global_capture_opts.use_pcapng);
  gtk_widget_set_tooltip_text(pcap_ng_cb, "Capture packets in the next-generation capture file format.");
  gtk_container_add(GTK_CONTAINER(left_vb), pcap_ng_cb);

  /* Capture length row */
  snap_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(left_vb), snap_hb);

  snap_cb = gtk_check_button_new_with_mnemonic("_Limit each packet to");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(snap_cb),
                               interface_opts.has_snaplen);
  g_signal_connect(snap_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(snap_cb,
    "Limit the maximum number of bytes to be captured from each packet. This size includes the "
    "link-layer header and all subsequent headers. ");
  gtk_box_pack_start(GTK_BOX(snap_hb), snap_cb, FALSE, FALSE, 0);

  snap_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) interface_opts.snaplen,
    MIN_PACKET_SIZE, WTAP_MAX_PACKET_SIZE, 1.0, 10.0, 0.0);
  snap_sb = gtk_spin_button_new (snap_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (snap_sb), TRUE);
  gtk_widget_set_size_request(snap_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(snap_hb), snap_sb, FALSE, FALSE, 0);

  snap_lb = gtk_label_new("bytes");
  gtk_misc_set_alignment(GTK_MISC(snap_lb), 0, 0.5f);
  gtk_box_pack_start(GTK_BOX(snap_hb), snap_lb, FALSE, FALSE, 0);

  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(capture_vb), filter_hb, FALSE, FALSE, 0);

  filter_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_CAPTURE_FILTER_ENTRY);
  g_signal_connect(filter_bt, "clicked", G_CALLBACK(capture_filter_construct_cb), NULL);
  g_signal_connect(filter_bt, "destroy", G_CALLBACK(filter_button_destroy_cb), NULL);
  gtk_widget_set_tooltip_text(filter_bt,
    "Select a capture filter to reduce the amount of packets to be captured. "
    "See \"Capture Filters\" in the online help for further information how to use it."
    );
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, FALSE, 3);

  /* Create the capture filter combo box*/
#if GTK_CHECK_VERSION(2,24,0)
  filter_cm = gtk_combo_box_text_new_with_entry ();
#else
  filter_cm = gtk_combo_box_entry_new_text ();
#endif
  cfilter_list = g_object_get_data(G_OBJECT(top_level), E_CFILTER_FL_KEY);
  g_object_set_data(G_OBJECT(top_level), E_CFILTER_FL_KEY, cfilter_list);
  g_object_set_data(G_OBJECT(top_level), E_CFILTER_CM_KEY, filter_cm);
  filter_te = gtk_bin_get_child(GTK_BIN(filter_cm));
  colorize_filter_te_as_empty(filter_te);
  g_signal_connect(filter_te, "changed", G_CALLBACK(capture_filter_check_syntax_cb), NULL);

  if (cfilter_list != NULL){
    for (cf_entry = cfilter_list; cf_entry != NULL; cf_entry = g_list_next(cf_entry)) {
#if GTK_CHECK_VERSION(2,24,0)
      gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(filter_cm), cf_entry->data);
#else
      gtk_combo_box_append_text(GTK_COMBO_BOX(filter_cm), cf_entry->data);
#endif
    }
  }
  if (g_array_index(global_capture_opts.ifaces, interface_options, 0).cfilter)
#if GTK_CHECK_VERSION(2,24,0)
    gtk_combo_box_text_prepend_text(GTK_COMBO_BOX_TEXT(filter_cm), g_array_index(global_capture_opts.ifaces, interface_options, 0).cfilter);
#else
    gtk_combo_box_prepend_text(GTK_COMBO_BOX(filter_cm), g_array_index(global_capture_opts.ifaces, interface_options, 0).cfilter);
#endif
  gtk_widget_set_tooltip_text(filter_cm,
    "Enter a capture filter to reduce the amount of packets to be captured. "
    "See \"Capture Filters\" in the online help for further information how to use it. "
    "Syntax checking can be disabled in Preferences -> Capture -> Syntax check capture filter."
    );
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_cm, TRUE, TRUE, 3);

  /* let an eventually capture filters dialog know the text entry to fill in */
  g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);

#if defined(HAVE_PCAP_OPEN_DEAD) && defined(HAVE_BPF_IMAGE)
  compile_bt = gtk_button_new_with_label("Compile BPF");
  g_signal_connect(compile_bt, "clicked", G_CALLBACK(capture_filter_compile_cb), NULL);
  gtk_widget_set_tooltip_text(compile_bt,
   "Compile the capture filter expression and show the BPF (Berkeley Packet Filter) code.");
  gtk_box_pack_start(GTK_BOX(filter_hb), compile_bt, FALSE, FALSE, 3);
#endif

  /* advanced row */
#ifdef HAVE_AIRPCAP
  advanced_bt = gtk_button_new_with_label("Wireless Settings");

  /* Both the callback and the data are global */
  g_signal_connect(advanced_bt,"clicked", G_CALLBACK(options_airpcap_advanced_cb),airpcap_tb);
  g_object_set_data(G_OBJECT(gtk_bin_get_child(GTK_BIN(if_cb))),AIRPCAP_OPTIONS_ADVANCED_KEY,advanced_bt);

  if(airpcap_if_selected != NULL) {
    /* It is an airpcap interface */
    gtk_widget_set_sensitive(advanced_bt,TRUE);
  } else {
    gtk_widget_set_sensitive(advanced_bt,FALSE);
  }

  gtk_box_pack_start(GTK_BOX(right_vb),advanced_bt,FALSE,FALSE,0);
  gtk_widget_show(advanced_bt);
#endif

#ifdef HAVE_PCAP_REMOTE
  remote_bt = gtk_button_new_with_label("Remote Settings");
  gtk_widget_set_tooltip_text(remote_bt, "Various settings for remote capture.");

  /* Both the callback and the data are global */
  g_signal_connect(remote_bt,"clicked", G_CALLBACK(options_remote_cb),NULL);
  g_object_set_data(G_OBJECT(iftype_cbx), E_OPT_REMOTE_BT_KEY, remote_bt);

  if (interface_opts.src_type == CAPTURE_IFREMOTE) {
    gtk_widget_set_sensitive(remote_bt, TRUE);
  } else {
    gtk_widget_set_sensitive(remote_bt, FALSE);
  }

  gtk_box_pack_start(GTK_BOX(right_vb),remote_bt,FALSE,FALSE,0);
  gtk_widget_show(remote_bt);
#endif

#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  buffer_size_hb = gtk_hbox_new(FALSE, 3);
  buffer_size_lb = gtk_label_new("Buffer size:");
  gtk_box_pack_start (GTK_BOX(buffer_size_hb), buffer_size_lb, FALSE, FALSE, 0);

  buffer_size_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) interface_opts.buffer_size,
    1, 65535, 1.0, 10.0, 0.0);
  buffer_size_sb = gtk_spin_button_new (buffer_size_adj, 0, 0);
  gtk_spin_button_set_value(GTK_SPIN_BUTTON (buffer_size_sb), (gfloat) interface_opts.buffer_size);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (buffer_size_sb), TRUE);
  gtk_widget_set_size_request(buffer_size_sb, 80, -1);
  gtk_widget_set_tooltip_text(buffer_size_sb,
   "The memory buffer size used while capturing. If you notice packet drops, you can try to increase this size.");
  gtk_box_pack_start (GTK_BOX(buffer_size_hb), buffer_size_sb, FALSE, FALSE, 0);

  buffer_size_lb = gtk_label_new("megabyte(s)");
  gtk_box_pack_start (GTK_BOX(buffer_size_hb), buffer_size_lb, FALSE, FALSE, 3);
  gtk_box_pack_start (GTK_BOX(right_vb), buffer_size_hb, FALSE, FALSE, 0);
#endif

  main_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(main_hb), 0);
  gtk_container_add(GTK_CONTAINER(main_vb), main_hb);

  left_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(left_vb), 0);
  gtk_box_pack_start(GTK_BOX(main_hb), left_vb, TRUE, TRUE, 0);

  right_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(right_vb), 0);
  gtk_box_pack_start(GTK_BOX(main_hb), right_vb, FALSE, FALSE, 0);

  /* Capture file-related options frame */
  file_fr = gtk_frame_new("Capture File(s)");
  gtk_container_add(GTK_CONTAINER(left_vb), file_fr);

  file_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(file_vb), 5);
  gtk_container_add(GTK_CONTAINER(file_fr), file_vb);

  /* File row */
  file_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(file_vb), file_hb, FALSE, FALSE, 0);

  file_lb = gtk_label_new("File:");
  gtk_box_pack_start(GTK_BOX(file_hb), file_lb, FALSE, FALSE, 3);

  file_te = gtk_entry_new();
  gtk_widget_set_tooltip_text(file_te,
    "Enter the file name to which captured data will be written. "
    "If you don't enter something here, a temporary file will be used."
     );
  gtk_box_pack_start(GTK_BOX(file_hb), file_te, TRUE, TRUE, 3);

  file_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_BROWSE);
  gtk_widget_set_tooltip_text(file_bt,
    "Select a file to which captured data will be written, "
    "instead of entering the file name directly. "
    );
  gtk_box_pack_start(GTK_BOX(file_hb), file_bt, FALSE, FALSE, 0);

  g_signal_connect(file_bt, "clicked", G_CALLBACK(capture_prep_file_cb), file_te);

  /* multiple files table */
  multi_tb = gtk_table_new(5, 3, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE(multi_tb), 1);
  gtk_table_set_col_spacings(GTK_TABLE(multi_tb), 3);
  gtk_box_pack_start(GTK_BOX(file_vb), multi_tb, FALSE, FALSE, 0);
  row = 0;

  /* multiple files row */
  multi_files_on_cb = gtk_check_button_new_with_mnemonic("Use _multiple files");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(multi_files_on_cb),
                               global_capture_opts.multi_files_on);
  g_signal_connect(multi_files_on_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity),
                 cap_open_w);
  gtk_widget_set_tooltip_text(multi_files_on_cb,
    "Instead of using a single capture file, multiple files will be created. "
    "The generated file names will contain an incrementing number and the start time of the capture.");
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), multi_files_on_cb, 0, 1, row, row+1);
  row++;

  /* Ring buffer filesize row */
  ring_filesize_cb = gtk_check_button_new_with_label("Next file every");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ring_filesize_cb),
                               global_capture_opts.has_autostop_filesize || !global_capture_opts.has_file_duration);
  g_signal_connect(ring_filesize_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(ring_filesize_cb,
    "If the selected file size is exceeded, capturing switches to the next file.\n"
    "PLEASE NOTE: at least one of the \"Next file every\" options MUST be selected.");
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), ring_filesize_cb, 0, 1, row, row+1);

  ring_filesize_adj = (GtkAdjustment *) gtk_adjustment_new(0.0,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  ring_filesize_sb = gtk_spin_button_new (ring_filesize_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ring_filesize_sb), TRUE);
  gtk_widget_set_size_request(ring_filesize_sb, 80, -1);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), ring_filesize_sb, 1, 2, row, row+1);

  ring_filesize_cbx = size_unit_combo_box_new(global_capture_opts.autostop_filesize);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), ring_filesize_cbx, 2, 3, row, row+1);

  value = size_unit_combo_box_set_value(global_capture_opts.autostop_filesize);
  gtk_adjustment_set_value(ring_filesize_adj, (gfloat) value);

  row++;

  /* Ring buffer duration row */
  file_duration_cb = gtk_check_button_new_with_label("Next file every");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(file_duration_cb),
                               global_capture_opts.has_file_duration);
  g_signal_connect(file_duration_cb, "toggled",
                   G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(file_duration_cb,
    "If the selected duration is exceeded, capturing switches to the next file.\n"
    "PLEASE NOTE: at least one of the \"Next file every\" options MUST be selected.");
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), file_duration_cb, 0, 1, row, row+1);

  file_duration_adj = (GtkAdjustment *)gtk_adjustment_new(0.0,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  file_duration_sb = gtk_spin_button_new (file_duration_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (file_duration_sb), TRUE);
  gtk_widget_set_size_request(file_duration_sb, 80, -1);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), file_duration_sb, 1, 2, row, row+1);

  file_duration_cbx = time_unit_combo_box_new(global_capture_opts.file_duration);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), file_duration_cbx, 2, 3, row, row+1);

  value = time_unit_combo_box_convert_value(global_capture_opts.file_duration);
  gtk_adjustment_set_value(file_duration_adj, (gfloat) value);
  row++;

  /* Ring buffer files row */
  ringbuffer_nbf_cb = gtk_check_button_new_with_label("Ring buffer with");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb),
                               global_capture_opts.has_ring_num_files);
  g_signal_connect(ringbuffer_nbf_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(ringbuffer_nbf_cb,
    "After capturing has switched to the next file and the given number of files has exceeded, "
    "the oldest file will be removed."
    );
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), ringbuffer_nbf_cb, 0, 1, row, row+1);

  ringbuffer_nbf_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) global_capture_opts.ring_num_files,
    2/*RINGBUFFER_MIN_NUM_FILES*/, RINGBUFFER_MAX_NUM_FILES, 1.0, 10.0, 0.0);
  ringbuffer_nbf_sb = gtk_spin_button_new (ringbuffer_nbf_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ringbuffer_nbf_sb), TRUE);
  gtk_widget_set_size_request(ringbuffer_nbf_sb, 80, -1);
  g_signal_connect(ringbuffer_nbf_sb, "changed", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), ringbuffer_nbf_sb, 1, 2, row, row+1);

  ringbuffer_nbf_lb = gtk_label_new("files");
  gtk_misc_set_alignment(GTK_MISC(ringbuffer_nbf_lb), 0, 0.5f);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), ringbuffer_nbf_lb, 2, 3, row, row+1);
  row++;

  /* Files row */
  stop_files_cb = gtk_check_button_new_with_label("Stop capture after");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(stop_files_cb),
                               global_capture_opts.has_autostop_files);
  g_signal_connect(stop_files_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(stop_files_cb, "Stop capturing after the given number of \"file switches\" have been done.");
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), stop_files_cb, 0, 1, row, row+1);

  stop_files_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)global_capture_opts.autostop_files,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  stop_files_sb = gtk_spin_button_new (stop_files_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (stop_files_sb), TRUE);
  gtk_widget_set_size_request(stop_files_sb, 80, -1);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), stop_files_sb, 1, 2, row, row+1);

  stop_files_lb = gtk_label_new("file(s)");
  gtk_misc_set_alignment(GTK_MISC(stop_files_lb), 0, 0.5f);
  gtk_table_attach_defaults(GTK_TABLE(multi_tb), stop_files_lb, 2, 3, row, row+1);
  row++;

  /* Capture limits frame */
  limit_fr = gtk_frame_new("Stop Capture ...");
  gtk_container_add(GTK_CONTAINER(left_vb), limit_fr);

  limit_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(limit_vb), 5);
  gtk_container_add(GTK_CONTAINER(limit_fr), limit_vb);

  /* limits table */
  limit_tb = gtk_table_new(3, 3, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE(limit_tb), 1);
  gtk_table_set_col_spacings(GTK_TABLE(limit_tb), 3);
  gtk_box_pack_start(GTK_BOX(limit_vb), limit_tb, FALSE, FALSE, 0);
  row = 0;

  /* Packet count row */
  stop_packets_cb = gtk_check_button_new_with_label("... after");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(stop_packets_cb),
                               global_capture_opts.has_autostop_packets);
  g_signal_connect(stop_packets_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(stop_packets_cb, "Stop capturing after the given number of packets have been captured.");
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_packets_cb, 0, 1, row, row+1);

  stop_packets_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)global_capture_opts.autostop_packets,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  stop_packets_sb = gtk_spin_button_new (stop_packets_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (stop_packets_sb), TRUE);
  gtk_widget_set_size_request(stop_packets_sb, 80, -1);
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_packets_sb, 1, 2, row, row+1);

  stop_packets_lb = gtk_label_new("packet(s)");
  gtk_misc_set_alignment(GTK_MISC(stop_packets_lb), 0, 0.5f);
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_packets_lb, 2, 3, row, row+1);
  row++;

  /* Filesize row */
  stop_filesize_cb = gtk_check_button_new_with_label("... after");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(stop_filesize_cb),
                               global_capture_opts.has_autostop_filesize);
  g_signal_connect(stop_filesize_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(stop_filesize_cb, "Stop capturing after the given amount of capture data has been captured.");
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_filesize_cb, 0, 1, row, row+1);

  stop_filesize_adj = (GtkAdjustment *) gtk_adjustment_new(0.0,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  stop_filesize_sb = gtk_spin_button_new (stop_filesize_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (stop_filesize_sb), TRUE);
  gtk_widget_set_size_request(stop_filesize_sb, 80, -1);
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_filesize_sb, 1, 2, row, row+1);

  stop_filesize_cbx = size_unit_combo_box_new(global_capture_opts.autostop_filesize);
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_filesize_cbx, 2, 3, row, row+1);

  value = size_unit_combo_box_set_value(global_capture_opts.autostop_filesize);
  gtk_adjustment_set_value(stop_filesize_adj, (gfloat) value);

  row++;

  /* Duration row */
  stop_duration_cb = gtk_check_button_new_with_label("... after");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(stop_duration_cb),
                               global_capture_opts.has_autostop_duration);
  g_signal_connect(stop_duration_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(stop_duration_cb, "Stop capturing after the given time is exceeded.");
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_duration_cb, 0, 1, row, row+1);

  stop_duration_adj = (GtkAdjustment *) gtk_adjustment_new(0.0,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  stop_duration_sb = gtk_spin_button_new (stop_duration_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (stop_duration_sb), TRUE);
  gtk_widget_set_size_request(stop_duration_sb, 80, -1);
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_duration_sb, 1, 2, row, row+1);

  stop_duration_cbx = time_unit_combo_box_new(global_capture_opts.autostop_duration);
  gtk_table_attach_defaults(GTK_TABLE(limit_tb), stop_duration_cbx, 2, 3, row, row+1);

  value = time_unit_combo_box_convert_value(global_capture_opts.autostop_duration);
  gtk_adjustment_set_value(stop_duration_adj, (gfloat) value);
  row++;

  /* Display-related options frame */
  display_fr = gtk_frame_new("Display Options");
  gtk_container_add(GTK_CONTAINER(right_vb), display_fr);

  display_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(display_vb), 5);
  gtk_container_add(GTK_CONTAINER(display_fr), display_vb);

  /* "Update display in real time" row */
  sync_cb = gtk_check_button_new_with_mnemonic(
      "_Update list of packets in real time");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(sync_cb),
                               global_capture_opts.real_time_mode);
  g_signal_connect(sync_cb, "toggled", G_CALLBACK(capture_prep_adjust_sensitivity), cap_open_w);
  gtk_widget_set_tooltip_text(sync_cb,
    "Using this option will show the captured packets immediately on the main screen. "
    "Please note: this will slow down capturing, so increased packet drops might appear.");
  gtk_container_add(GTK_CONTAINER(display_vb), sync_cb);

  /* "Auto-scroll live update" row */
  auto_scroll_cb = gtk_check_button_new_with_mnemonic("_Automatic scrolling in live capture");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(auto_scroll_cb), auto_scroll_live);
  gtk_widget_set_tooltip_text(auto_scroll_cb,
    "This will scroll the \"Packet List\" automatically to the latest captured packet, "
    "when the \"Update List of packets in real time\" option is used.");
  gtk_container_add(GTK_CONTAINER(display_vb), auto_scroll_cb);

  /* "Hide capture info" row */
  hide_info_cb = gtk_check_button_new_with_mnemonic("_Hide capture info dialog");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(hide_info_cb), !global_capture_opts.show_info);
  gtk_widget_set_tooltip_text(hide_info_cb, "Hide the capture info dialog while capturing.");
  gtk_container_add(GTK_CONTAINER(display_vb), hide_info_cb);

  /* Name Resolution frame */
  resolv_fr = gtk_frame_new("Name Resolution");
  gtk_container_add(GTK_CONTAINER(right_vb), resolv_fr);

  resolv_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(resolv_vb), 5);
  gtk_container_add(GTK_CONTAINER(resolv_fr), resolv_vb);

  m_resolv_cb = gtk_check_button_new_with_mnemonic(
                "Enable _MAC name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(m_resolv_cb),
                gbl_resolv_flags & RESOLV_MAC);
  gtk_widget_set_tooltip_text(m_resolv_cb, "Perform MAC layer name resolution while capturing.");
  gtk_container_add(GTK_CONTAINER(resolv_vb), m_resolv_cb);

  n_resolv_cb = gtk_check_button_new_with_mnemonic(
                "Enable _network name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(n_resolv_cb),
                gbl_resolv_flags & RESOLV_NETWORK);
  gtk_widget_set_tooltip_text(n_resolv_cb, "Perform network layer name resolution while capturing.");
  gtk_container_add(GTK_CONTAINER(resolv_vb), n_resolv_cb);

  t_resolv_cb = gtk_check_button_new_with_mnemonic(
                "Enable _transport name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_resolv_cb),
                gbl_resolv_flags & RESOLV_TRANSPORT);
  gtk_widget_set_tooltip_text(t_resolv_cb,
    "Perform transport layer name resolution while capturing.");
  gtk_container_add(GTK_CONTAINER(resolv_vb), t_resolv_cb);

  /* Button row: "Start", "Cancel" and "Help" buttons */
  bbox = dlg_button_row_new(WIRESHARK_STOCK_CAPTURE_START, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);

  ok_bt = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CAPTURE_START);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(capture_start_cb), NULL);
  gtk_widget_set_tooltip_text(ok_bt,
    "Start the capture process.");

  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  gtk_widget_set_tooltip_text(cancel_bt,
    "Cancel and exit dialog.");
  window_set_cancel_button(cap_open_w, cancel_bt, capture_cancel_cb);

  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  gtk_widget_set_tooltip_text(help_bt,
    "Show help about capturing.");
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_CAPTURE_OPTIONS_DIALOG);

  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  gtk_widget_grab_default(ok_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
#ifdef HAVE_PCAP_REMOTE
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_REMOTE_DIALOG_PTR_KEY, NULL);
#endif
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_SNAP_CB_KEY, snap_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_SNAP_SB_KEY, snap_sb);
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_BUFFER_SIZE_SB_KEY, buffer_size_sb);
#endif
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_PROMISC_KEY, promisc_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_PCAP_NG_KEY, pcap_ng_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_FILT_KEY,  filter_te);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_FILE_TE_KEY,  file_te);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_MULTI_FILES_ON_CB_KEY,  multi_files_on_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_RING_NBF_CB_KEY,  ringbuffer_nbf_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_RING_NBF_SB_KEY,  ringbuffer_nbf_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_RING_NBF_LB_KEY,  ringbuffer_nbf_lb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_RING_FILESIZE_CB_KEY,  ring_filesize_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_RING_FILESIZE_SB_KEY,  ring_filesize_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_RING_FILESIZE_CBX_KEY,  ring_filesize_cbx);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_FILE_DURATION_CB_KEY,  file_duration_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_FILE_DURATION_SB_KEY,  file_duration_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_FILE_DURATION_CBX_KEY,  file_duration_cbx);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_SYNC_KEY,  sync_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_AUTO_SCROLL_KEY, auto_scroll_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_HIDE_INFO_KEY, hide_info_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_PACKETS_CB_KEY, stop_packets_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_PACKETS_SB_KEY, stop_packets_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_PACKETS_LB_KEY, stop_packets_lb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_FILESIZE_CB_KEY, stop_filesize_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_FILESIZE_SB_KEY, stop_filesize_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_FILESIZE_CBX_KEY, stop_filesize_cbx);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_DURATION_CB_KEY,  stop_duration_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_DURATION_SB_KEY,  stop_duration_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_DURATION_CBX_KEY,  stop_duration_cbx);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_FILES_CB_KEY, stop_files_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_FILES_SB_KEY, stop_files_sb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_STOP_FILES_LB_KEY, stop_files_lb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_M_RESOLVE_KEY,  m_resolv_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_N_RESOLVE_KEY,  n_resolv_cb);
  g_object_set_data(G_OBJECT(cap_open_w), E_CAP_T_RESOLVE_KEY,  t_resolv_cb);

  /* Set the sensitivity of various widgets as per the settings of other
     widgets. */
  capture_prep_adjust_sensitivity(NULL, cap_open_w);

  /* Catch the "activate" signal on the text
     entries, so that if the user types Return there, we act as if the
     "OK" button had been selected, as happens if Return is typed if some
     widget that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(gtk_bin_get_child(GTK_BIN(if_cb)), ok_bt);
  dlg_set_activate(filter_te, ok_bt);
  dlg_set_activate(file_te, ok_bt);

  /* XXX - why does not

     gtk_widget_grab_focus(if_cb);

    give the initial focus to the "Interface" combo box?

    Or should I phrase that as "why does GTK+ continually frustrate
    attempts to make GUIs driveable from the keyboard?"  We have to
    go catch the activate signal on every single GtkEntry widget
    (rather than having widgets whose activate signal is *not*
    caught not catch the Return keystroke, so that it passes on,
    ultimately, to the window, which can activate the default
    widget, i.e. the "OK" button); we have to catch the "key_press_event"
    signal and have the handler check for ESC, so that we can have ESC
    activate the "Cancel" button; in order to support Alt+<key> mnemonics
    for buttons and the like, we may have to construct an accelerator
    group by hand and set up the accelerators by hand (if that even
    works - I've not tried it yet); we have to do a "gtk_widget_grab_focus()"
    to keep some container widget from getting the initial focus, so that
    you don't have to tab into the first widget in order to start typing
    in it; and it now appears that you simply *can't* make a combo box
    get the initial focus, at least not in the obvious fashion. Sigh.... */

  g_signal_connect(cap_open_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(cap_open_w, "destroy", G_CALLBACK(capture_prep_destroy_cb), NULL);

  /* Give the initial focus to the "Filter" entry box. */
  gtk_widget_grab_focus(filter_te);

  gtk_widget_show_all(cap_open_w);
  window_present(cap_open_w);

  cap_open_complete = TRUE;   /* "Capture:Start" is now OK */
}

/* everythings prepared, now it's really time to start the capture */
void
capture_start_confirmed(void)
{


  interface_options interface_opts;
  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
  /* init iface, if never used before */
  /* XXX - would better be doing this in main.c */
  if(interface_opts.name == NULL) {
    gchar *if_device;
    const gchar *if_name;

    /* did the user ever selected a capture interface before? */
    if(prefs.capture_device == NULL) {
      simple_dialog(ESD_TYPE_CONFIRMATION,
                    ESD_BTN_OK,
                    "%sNo capture interface selected!%s\n\n"
                    "To select an interface use:\n\n"
                    "Capture->Options (until Wireshark is stopped)\n"
                    "Edit->Preferences/Capture (permanent, if saved)",
                    simple_dialog_primary_start(), simple_dialog_primary_end());
      return;
    }
    if_device = g_strdup(prefs.capture_device);
    if_name = get_if_name(if_device);
    interface_opts.name = g_strdup(if_name);
    interface_opts.descr = get_interface_descriptive_name(interface_opts.name);

    g_free(if_device);
  }

  /* XXX - we might need to init other pref data as well... */
  menu_auto_scroll_live_changed(auto_scroll_live);

  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  if (capture_start(&global_capture_opts)) {
    /* The capture succeeded, which means the capture filter syntax is
       valid; add this capture filter to the recent capture filter list. */
    cfilter_combo_add_recent(interface_opts.cfilter);
  }
}

/* user confirmed the "Save capture file..." dialog */
static void
capture_start_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
  switch(btn) {
  case(ESD_BTN_SAVE):
    /* save file first */
    file_save_as_cmd(after_save_capture_dialog, data);
    break;
  case(ESD_BTN_DONT_SAVE):
    /* XXX - unlink old file? */
    /* start the capture */
    capture_start_confirmed();
    break;
  case(ESD_BTN_CANCEL):
    break;
  default:
    g_assert_not_reached();
  }
}

/* user pressed the "Start" button (in dialog or toolbar) */
void
capture_start_cb(GtkWidget *w _U_, gpointer d _U_)
{
  gpointer  dialog;
  gchar *if_name;
  cap_settings_t *cap_settings_p = NULL;
  interface_options interface_opts;
  guint i;

#ifdef HAVE_AIRPCAP
  airpcap_if_active = airpcap_if_selected;
  airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif

#ifdef _WIN32
  /* Is WPcap loaded? */
  if (!has_wpcap) {
    char * err_msg = cant_load_winpcap_err("Wireshark");

    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, err_msg);
    g_free(err_msg);
    return;
  }
#endif

  if (cap_open_w) {
    /*
     * There's an options dialog; get the values from it and close it.
     */
    gboolean success;

    /* Determine if "capture start" while building of the "capture options" window */
    /*  is in progress. If so, ignore the "capture start.                          */
    /* XXX: Would it be better/cleaner for the "capture options" window code to    */
    /*      disable the capture start button temporarily ?                         */
    if (cap_open_complete == FALSE) {
      return;  /* Building options window: ignore "capture start" */
    }
    success = capture_dlg_prep(cap_open_w);
    window_destroy(GTK_WIDGET(cap_open_w));
    if (!success)
      return;   /* error in options dialog */
  }

#ifndef USE_THREADS
  if (global_capture_opts.ifaces->len > 1) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "You specified multiple interfaces for capturing which this version of Wireshark doesn't support.");
    return;
  }
#endif
  if (global_capture_opts.ifaces->len == 0) {
    if (prefs.capture_device == NULL) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "You didn't specify an interface on which to capture packets.");
      return;
    }
    interface_opts.name = g_strdup(get_if_name(prefs.capture_device));
    interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
    interface_opts.monitor_mode = prefs_capture_device_monitor_mode(interface_opts.name);
    interface_opts.linktype = capture_dev_user_linktype_find(interface_opts.name);
    interface_opts.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
    interface_opts.snaplen = global_capture_opts.default_options.snaplen;
    interface_opts.has_snaplen = global_capture_opts.default_options.has_snaplen;
    interface_opts.promisc_mode = global_capture_opts.default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    interface_opts.buffer_size =  global_capture_opts.default_options.buffer_size;
#endif
#ifdef HAVE_PCAP_REMOTE
    interface_opts.src_type = global_capture_opts.default_options.src_type;
    interface_opts.remote_host = g_strdup(global_capture_opts.default_options.remote_host);
    interface_opts.remote_port = g_strdup(global_capture_opts.default_options.remote_port);
    interface_opts.auth_type = global_capture_opts.default_options.auth_type;
    interface_opts.auth_username = g_strdup(global_capture_opts.default_options.auth_username);
    interface_opts.auth_password = g_strdup(global_capture_opts.default_options.auth_password);
    interface_opts.datatx_udp = global_capture_opts.default_options.datatx_udp;
    interface_opts.nocap_rpcap = global_capture_opts.default_options.nocap_rpcap;
    interface_opts.nocap_local = global_capture_opts.default_options.nocap_local;
 #endif
 #ifdef HAVE_PCAP_SETSAMPLING
    interface_opts.sampling_method = global_capture_opts.default_options.sampling_method;
    interface_opts.sampling_param  = global_capture_opts.default_options.sampling_param;
 #endif
    g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  }

  if (cap_settings_history != NULL) {
    for (i = 0; i < global_capture_opts.ifaces->len; i++) {
      interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
      if_name = g_strdup(interface_opts.name);
      cap_settings_p = g_hash_table_lookup(cap_settings_history, if_name);
      if (cap_settings_p == NULL) {
        cap_settings_p = g_malloc(sizeof (cap_settings_t));
        g_hash_table_insert(cap_settings_history, if_name, cap_settings_p);
      } else {
        g_free(if_name);
      }
      cap_settings_p->monitor_mode = interface_opts.monitor_mode;
      cap_settings_p->linktype = interface_opts.linktype;
    }
  }

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                "%sSave capture file before starting a new capture?%s\n\n"
                "If you start a new capture without saving, your current capture data will\nbe discarded.",
                simple_dialog_primary_start(), simple_dialog_primary_end());
    simple_dialog_set_cb(dialog, capture_start_answered_cb, NULL);
  } else {
    /* unchanged file, just capture a new one */
    capture_start_confirmed();
  }
}

static void
capture_cancel_cb(GtkWidget *win, gpointer data)
{
#ifdef HAVE_PCAP_REMOTE
  interface_options interface_opts;

  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
  if (g_hash_table_size (remote_host_list) == 0) {
    /* Ensure we fall back to local interfaces */
    interface_opts.src_type = CAPTURE_IFLOCAL;

    if (interface_opts.name) {
      g_free (interface_opts.name);
      interface_opts.name = NULL;
    }
    if (interface_opts.descr) {
      g_free (interface_opts.descr);
      interface_opts.descr = NULL;
    }
  }
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
#endif

  window_cancel_button_cb (win, data);
}

/* user change linktype selection;, convert to internal DLT value */
static void
select_link_type_cb(GtkWidget *linktype_combo_box, gpointer data _U_)
{
  gpointer  ptr;
  int       dlt;
  interface_options interface_opts;

  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);

  if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(linktype_combo_box), &ptr)) {
    g_assert_not_reached();  /* Programming error: somehow nothing is active */
  }
  if ((dlt = GPOINTER_TO_INT(ptr)) == -1) {
    g_assert_not_reached();  /* Programming error: somehow managed to select an "unsupported" entry */
  }
  interface_opts.linktype = dlt;
  capture_filter_check_syntax_cb(linktype_combo_box, data);
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
}

#ifdef HAVE_PCAP_REMOTE
static gboolean
free_remote_host (gpointer key _U_, gpointer value, gpointer user _U_)
{
  struct remote_host *rh = value;

  g_free (rh->remote_host);
  g_free (rh->remote_port);
  g_free (rh->auth_username);
  g_free (rh->auth_password);

  return TRUE;
}

/* user selected an interface type (local/remote), convert to internal value) */
static void
select_if_type_cb(GtkComboBox *iftype_cbx, gpointer data _U_)
{
  int new_iftype = gtk_combo_box_get_active(GTK_COMBO_BOX(iftype_cbx));
  int old_iftype = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                                     E_CAP_CBX_IFTYPE_VALUE_KEY));
  int no_update = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx),
                                                    E_CAP_CBX_IFTYPE_NOUPDATE_KEY));
  gint num_remote = g_hash_table_size (remote_host_list);
  interface_options interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);

  if (new_iftype == CAPTURE_IFREMOTE) {
    g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_PREV_IFTYPE_VALUE_KEY,
                      GINT_TO_POINTER(old_iftype));
    capture_remote_cb(GTK_WIDGET(iftype_cbx), FALSE);
  } else if (new_iftype != old_iftype) {
    if (new_iftype > CAPTURE_IFREMOTE) {
      if (new_iftype == num_remote + 4)
      {
        /* The user selected the "Clear list" entry */
        new_iftype = CAPTURE_IFLOCAL;
        gtk_combo_box_set_active(GTK_COMBO_BOX(iftype_cbx), new_iftype);
        g_hash_table_foreach_remove (remote_host_list, free_remote_host, NULL);
        num_remote += 3;
        while (num_remote--)  /* Remove separator lines and "Clear" item */
          gtk_combo_box_remove_text (iftype_cbx, 2);
      } else {
        struct remote_host *rh;
        gchar *string;
        string = gtk_combo_box_get_active_text (GTK_COMBO_BOX(iftype_cbx));
        rh = g_hash_table_lookup (remote_host_list, string);
        g_free (string);

        g_free(interface_opts.remote_host);
        interface_opts.remote_host = g_strdup(rh->remote_host);
        g_free(interface_opts.remote_port);
        interface_opts.remote_port = g_strdup(rh->remote_port);
        interface_opts.auth_type = rh->auth_type;
        if (interface_opts.auth_type == CAPTURE_AUTH_PWD && strlen(rh->auth_username) == 0) {
          /* Empty username, ask for one */
          capture_remote_cb(GTK_WIDGET(iftype_cbx), TRUE);
          no_update = TRUE;
        } else {
          /* Already entered username and password */
          g_free(interface_opts.auth_username);
          interface_opts.auth_username = g_strdup(rh->auth_username);
          g_free(interface_opts.auth_password);
          interface_opts.auth_password = g_strdup(rh->auth_password);
        }
      }
    }
    if (!no_update) {
      g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_PREV_IFTYPE_VALUE_KEY,
                        GINT_TO_POINTER(old_iftype));
      g_object_set_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_VALUE_KEY,
                        GINT_TO_POINTER(new_iftype));
      update_interface_list();
    }
  }
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
}
#endif

/* user pressed "File" button */
static void
capture_prep_file_cb(GtkWidget *file_bt, GtkWidget *file_te)
{
  file_selection_browse(file_bt, file_te, "Wireshark: Specify a Capture File", FILE_SELECTION_WRITE_BROWSE);
}


/* convert dialog settings into capture_opts values */
static gboolean
capture_dlg_prep(gpointer parent_w) {
  GtkWidget *if_cb, *snap_cb, *snap_sb, *promisc_cb,
#ifdef HAVE_PCAP_CREATE
            *monitor_cb,
#endif
            *pcap_ng_cb,*filter_cm,
            *file_te, *multi_files_on_cb, *ringbuffer_nbf_sb, *ringbuffer_nbf_cb,
            *sync_cb, *auto_scroll_cb, *hide_info_cb,
            *stop_packets_cb, *stop_packets_sb,
            *stop_filesize_cb, *stop_filesize_sb, *stop_filesize_cbx,
            *stop_duration_cb, *stop_duration_sb, *stop_duration_cbx,
            *ring_filesize_cb, *ring_filesize_sb, *ring_filesize_cbx,
            *file_duration_cb, *file_duration_sb, *file_duration_cbx,
            *stop_files_cb, *stop_files_sb,
            *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
#ifdef HAVE_PCAP_REMOTE
  GtkWidget *iftype_cbx;
#endif
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  GtkWidget *buffer_size_sb;
#endif
  gchar *entry_text;
  gchar *if_text;
  const gchar *if_name;
  const gchar *filter_text;
  const gchar *g_save_file;
  gchar *cf_name;
  gchar *dirname;
  gint32 tmp;
  interface_options interface_opts;

if (global_capture_opts.ifaces->len > 0) {
  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
}

  if_cb      = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_IFACE_KEY);
#ifdef HAVE_PCAP_REMOTE
  iftype_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_IFTYPE_CBX_KEY);
#endif
  snap_cb    = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SNAP_CB_KEY);
  snap_sb    = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SNAP_SB_KEY);
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  buffer_size_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_BUFFER_SIZE_SB_KEY);
#endif
  promisc_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_PROMISC_KEY);
#ifdef HAVE_PCAP_CREATE
  monitor_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_MONITOR_KEY);
#endif
  pcap_ng_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_PCAP_NG_KEY);
  filter_cm  = g_object_get_data(G_OBJECT(top_level), E_CFILTER_CM_KEY);
 /* filter_te = gtk_bin_get_child(GTK_BIN(filter_cm));*/
  file_te    = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_TE_KEY);
  multi_files_on_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_MULTI_FILES_ON_CB_KEY);
  ringbuffer_nbf_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_NBF_CB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_NBF_SB_KEY);
  ring_filesize_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_FILESIZE_CB_KEY);
  ring_filesize_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_FILESIZE_SB_KEY);
  ring_filesize_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_FILESIZE_CBX_KEY);
  file_duration_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_DURATION_CB_KEY);
  file_duration_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_DURATION_SB_KEY);
  file_duration_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_DURATION_CBX_KEY);
  sync_cb   = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SYNC_KEY);
  auto_scroll_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_AUTO_SCROLL_KEY);
  hide_info_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_HIDE_INFO_KEY);
  stop_packets_cb   = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_PACKETS_CB_KEY);
  stop_packets_sb   = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_PACKETS_SB_KEY);
  stop_filesize_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILESIZE_CB_KEY);
  stop_filesize_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILESIZE_SB_KEY);
  stop_filesize_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILESIZE_CBX_KEY);
  stop_duration_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_DURATION_CB_KEY);
  stop_duration_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_DURATION_SB_KEY);
  stop_duration_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_DURATION_CBX_KEY);
  stop_files_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILES_CB_KEY);
  stop_files_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILES_SB_KEY);
  m_resolv_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_M_RESOLVE_KEY);
  n_resolv_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_N_RESOLVE_KEY);
  t_resolv_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_T_RESOLVE_KEY);

#if GTK_CHECK_VERSION(2,24,0)
  entry_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(if_cb));
#else
  entry_text = gtk_combo_box_get_active_text (GTK_COMBO_BOX(if_cb));
#endif /* GTK_CHECK_VERSION(2,24,0) */
  if(!entry_text)
    entry_text = '\0';

  if_text = g_strstrip(entry_text);
  if_name = get_if_name(if_text);
  if (*if_name == '\0') {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "You didn't specify an interface on which to capture packets.");
    g_free(entry_text);
    return FALSE;
  }
  g_free(interface_opts.name);
  g_free(interface_opts.descr);
  interface_opts.name = g_strdup(if_name);
  interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
  g_free(entry_text);
  /* The Linktype is stored when the interface is changed, or if not,
     the acquisition will be performed on the default datalink for the device */
#ifdef HAVE_PCAP_REMOTE
  interface_opts.src_type = (capture_source)
      GPOINTER_TO_INT(g_object_get_data(G_OBJECT(iftype_cbx), E_CAP_CBX_IFTYPE_VALUE_KEY));
  if (interface_opts.src_type > CAPTURE_IFREMOTE)
    interface_opts.src_type = CAPTURE_IFREMOTE;
#endif

#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
  interface_opts.buffer_size =
    gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(buffer_size_sb));
#endif

  interface_opts.has_snaplen =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(snap_cb));
  if (interface_opts.has_snaplen) {
    interface_opts.snaplen =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(snap_sb));
    if (interface_opts.snaplen < 1)
      interface_opts.snaplen = WTAP_MAX_PACKET_SIZE;
    else if (interface_opts.snaplen < MIN_PACKET_SIZE)
      interface_opts.snaplen = MIN_PACKET_SIZE;
  } else {
    interface_opts.snaplen = WTAP_MAX_PACKET_SIZE;
  }

  interface_opts.promisc_mode =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(promisc_cb));
#ifdef HAVE_PCAP_CREATE
  interface_opts.monitor_mode =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(monitor_cb));
#endif
  global_capture_opts.use_pcapng =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pcap_ng_cb));

  /* XXX - don't try to get clever and set "cfile.filter" to NULL if the
     filter string is empty, as an indication that we don't have a filter
     and thus don't have to set a filter when capturing - the version of
     libpcap in Red Hat Linux 6.1, and versions based on later patches
     in that series, don't bind the AF_PACKET socket to an interface
     until a filter is set, which means they aren't bound at all if
     no filter is set, which means no packets arrive as input on that
     socket, which means Wireshark never sees any packets. */
#if GTK_CHECK_VERSION(2,24,0)
  filter_text = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT(filter_cm));
#else
  filter_text = gtk_combo_box_get_active_text (GTK_COMBO_BOX(filter_cm));
#endif /* GTK_CHECK_VERSION(2,24,0 */
  if (interface_opts.cfilter)
    g_free(interface_opts.cfilter);
  g_assert(filter_text != NULL);
  interface_opts.cfilter = g_strdup(filter_text);

  /* Wireshark always saves to a capture file. */
  global_capture_opts.saving_to_file = TRUE;
  g_save_file = gtk_entry_get_text(GTK_ENTRY(file_te));
  if (g_save_file && g_save_file[0]) {
    /* User specified a file to which the capture should be written. */
    global_capture_opts.save_file = g_strdup(g_save_file);
    /* Save the directory name for future file dialogs. */
    cf_name = g_strdup(g_save_file);
    dirname = get_dirname(cf_name);  /* Overwrites cf_name */
    set_last_open_dir(dirname);
    g_free(cf_name);
  } else {
    /* User didn't specify a file; save to a temporary file. */
    global_capture_opts.save_file = NULL;
  }

  global_capture_opts.has_autostop_packets =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_packets_cb));
  if (global_capture_opts.has_autostop_packets)
    global_capture_opts.autostop_packets =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(stop_packets_sb));

  global_capture_opts.has_autostop_duration =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_duration_cb));
  if (global_capture_opts.has_autostop_duration) {
    global_capture_opts.autostop_duration =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(stop_duration_sb));
    global_capture_opts.autostop_duration =
      time_unit_combo_box_get_value(stop_duration_cbx, global_capture_opts.autostop_duration);
  }

  global_capture_opts.real_time_mode =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb));

  auto_scroll_live =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auto_scroll_cb));

  global_capture_opts.show_info =
      !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(hide_info_cb));

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(m_resolv_cb)))
    gbl_resolv_flags |= RESOLV_MAC;
  else
    gbl_resolv_flags &= ~RESOLV_MAC;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(n_resolv_cb)))
    gbl_resolv_flags |= RESOLV_NETWORK;
  else
    gbl_resolv_flags &= ~RESOLV_NETWORK;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(t_resolv_cb)))
    gbl_resolv_flags |= RESOLV_TRANSPORT;
  else
    gbl_resolv_flags &= ~RESOLV_TRANSPORT;

  global_capture_opts.has_ring_num_files =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb));

  global_capture_opts.ring_num_files =
    gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ringbuffer_nbf_sb));
  if (global_capture_opts.ring_num_files > RINGBUFFER_MAX_NUM_FILES)
    global_capture_opts.ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
  else if (global_capture_opts.ring_num_files < RINGBUFFER_MIN_NUM_FILES)
    global_capture_opts.ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif

  global_capture_opts.multi_files_on =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(multi_files_on_cb));

  global_capture_opts.has_file_duration =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(file_duration_cb));
  if (global_capture_opts.has_file_duration) {
    global_capture_opts.file_duration =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(file_duration_sb));
    global_capture_opts.file_duration =
      time_unit_combo_box_get_value(file_duration_cbx, global_capture_opts.file_duration);
  }

  global_capture_opts.has_autostop_files =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_files_cb));
  if (global_capture_opts.has_autostop_files)
    global_capture_opts.autostop_files =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(stop_files_sb));

  if (global_capture_opts.multi_files_on) {
    global_capture_opts.has_autostop_filesize =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_filesize_cb));
    if (global_capture_opts.has_autostop_filesize) {
      tmp = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ring_filesize_sb));
      tmp = size_unit_combo_box_convert_value(ring_filesize_cbx, tmp);
      if(tmp != 0) {
        global_capture_opts.autostop_filesize = tmp;
      } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
          "%sMultiple files: Requested filesize too large!%s\n\n"
          "The setting \"Next file every x byte(s)\" can't be greater than %u bytes (2GB).",
          simple_dialog_primary_start(), simple_dialog_primary_end(), G_MAXINT);
        return FALSE;
      }
    }

    /* test if the settings are ok for a ringbuffer */
    if (global_capture_opts.save_file == NULL) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "%sMultiple files: No capture file name given!%s\n\n"
        "You must specify a filename if you want to use multiple files.",
        simple_dialog_primary_start(), simple_dialog_primary_end());
      return FALSE;
    } else if (!global_capture_opts.has_autostop_filesize && !global_capture_opts.has_file_duration) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        "%sMultiple files: No file limit given!%s\n\n"
        "You must specify a file size or duration at which is switched to the next capture file\n"
        "if you want to use multiple files.",
        simple_dialog_primary_start(), simple_dialog_primary_end());
      g_free(global_capture_opts.save_file);
      global_capture_opts.save_file = NULL;
      return FALSE;
    }
  } else {
    global_capture_opts.has_autostop_filesize =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_filesize_cb));
    if (global_capture_opts.has_autostop_filesize) {
      tmp = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(stop_filesize_sb));
      tmp = size_unit_combo_box_convert_value(stop_filesize_cbx, tmp);
      if(tmp != 0) {
        global_capture_opts.autostop_filesize = tmp;
      } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
          "%sStop Capture: Requested filesize too large!%s\n\n"
          "The setting \"... after x byte(s)\" can't be greater than %u bytes (2GB).",
          simple_dialog_primary_start(), simple_dialog_primary_end(), G_MAXINT);
        return FALSE;
      }
    }
  } /* multi_files_on */
  g_array_insert_val(global_capture_opts.ifaces, 0, interface_opts);
  return TRUE;
}

/* user requested to destroy the dialog */
static void
capture_prep_destroy_cb(GtkWidget *win, gpointer user_data _U_)
{
  GtkWidget *fs;
#ifdef HAVE_PCAP_REMOTE
  GList     *if_list;
  GtkWidget *remote_w;
#endif

  /* Is there a file selection dialog associated with this
     Capture Options dialog? */
  fs = g_object_get_data(G_OBJECT(win), E_FILE_SEL_DIALOG_PTR_KEY);

#ifdef HAVE_PCAP_REMOTE
  if_list = (GList *) g_object_get_data(G_OBJECT(win), E_CAP_IF_LIST_KEY);
  if (if_list) {
      free_interface_list(if_list);
  }
#endif

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    window_destroy(fs);
  }

  /* Note that we no longer have a "Capture Options" dialog box. */
  cap_open_w = NULL;

#ifdef HAVE_AIRPCAP
  /* update airpcap toolbar */
  airpcap_set_toolbar_stop_capture(airpcap_if_active);
#endif

#ifdef HAVE_PCAP_REMOTE
  remote_w = g_object_get_data(G_OBJECT(win), E_CAP_REMOTE_DIALOG_PTR_KEY);
  if (remote_w != NULL)
      window_destroy(remote_w);
#endif
}

/* user changed the interface entry */
static void
capture_prep_interface_changed_cb(GtkWidget *entry, gpointer argp)
{
  set_if_capabilities(FALSE);
  capture_filter_check_syntax_cb(entry, argp);
}

#ifdef HAVE_PCAP_CREATE
/* user changed the setting of the monitor-mode checkbox */
static void
capture_prep_monitor_changed_cb(GtkWidget *monitor _U_, gpointer argp _U_)
{
  set_if_capabilities(TRUE);
}
#endif

/*
 * Adjust the sensitivity of various widgets as per the current setting
 * of other widgets.
 */
static void
capture_prep_adjust_sensitivity(GtkWidget *tb _U_, gpointer parent_w)
{
  GtkWidget *snap_cb, *snap_sb,
            *multi_files_on_cb, *ringbuffer_nbf_cb, *ringbuffer_nbf_sb, *ringbuffer_nbf_lb,
            *ring_filesize_cb, *ring_filesize_sb, *ring_filesize_cbx,
            *file_duration_cb, *file_duration_sb, *file_duration_cbx,
            *sync_cb, *auto_scroll_cb, /* *hide_info_cb, */
            *stop_packets_cb, *stop_packets_sb, *stop_packets_lb,
            *stop_filesize_cb, *stop_filesize_sb, *stop_filesize_cbx,
            *stop_duration_cb, *stop_duration_sb, *stop_duration_cbx,
            *stop_files_cb, *stop_files_sb, *stop_files_lb;

  snap_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SNAP_CB_KEY);
  snap_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SNAP_SB_KEY);
  multi_files_on_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_MULTI_FILES_ON_CB_KEY);
  ringbuffer_nbf_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_NBF_CB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_NBF_SB_KEY);
  ringbuffer_nbf_lb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_NBF_LB_KEY);
  ring_filesize_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_FILESIZE_CB_KEY);
  ring_filesize_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_FILESIZE_SB_KEY);
  ring_filesize_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_RING_FILESIZE_CBX_KEY);
  file_duration_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_DURATION_CB_KEY);
  file_duration_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_DURATION_SB_KEY);
  file_duration_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_FILE_DURATION_CBX_KEY);
  sync_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_SYNC_KEY);
  auto_scroll_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_AUTO_SCROLL_KEY);
  /*hide_info_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_HIDE_INFO_KEY);*/
  stop_packets_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_PACKETS_CB_KEY);
  stop_packets_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_PACKETS_SB_KEY);
  stop_packets_lb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_PACKETS_LB_KEY);
  stop_filesize_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILESIZE_CB_KEY);
  stop_filesize_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILESIZE_SB_KEY);
  stop_filesize_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILESIZE_CBX_KEY);
  stop_duration_cb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_DURATION_CB_KEY);
  stop_duration_sb  = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_DURATION_SB_KEY);
  stop_duration_cbx = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_DURATION_CBX_KEY);
  stop_files_cb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILES_CB_KEY);
  stop_files_sb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILES_SB_KEY);
  stop_files_lb = (GtkWidget *) g_object_get_data(G_OBJECT(parent_w), E_CAP_STOP_FILES_LB_KEY);

  /* The snapshot length spinbox is sensitive if the "Limit each packet
     to" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(snap_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(snap_cb)));


  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb))) {
    /* "Update list of packets in real time" captures enabled; we don't
       support ring buffer mode for those captures, so turn ring buffer
       mode off if it's on, and make its toggle button, and the spin
       button for the number of ring buffer files (and the spin button's
       label), insensitive. */
#if 0
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(multi_files_on_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(multi_files_on_cb), FALSE);
#endif

    /* Auto-scroll mode is meaningful only in "Update list of packets
       in real time" captures, so make its toggle button sensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(auto_scroll_cb), TRUE);

    /*gtk_widget_set_sensitive(GTK_WIDGET(hide_info_cb), TRUE);*/
  } else {
    /* "Update list of packets in real time" captures disabled; that
       means ring buffer mode is OK, so make its toggle button
       sensitive. */
/*    gtk_widget_set_sensitive(GTK_WIDGET(multi_files_on_cb), TRUE);*/

    /* Auto-scroll mode is meaningful only in "Update list of packets
       in real time" captures, so make its toggle button insensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(auto_scroll_cb), FALSE);

    /*gtk_widget_set_sensitive(GTK_WIDGET(hide_info_cb), FALSE);*/
  }

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(multi_files_on_cb))) {
    /* Ring buffer mode enabled. */

    /* Force at least one of the "file switch" conditions (we need at least one) */
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_filesize_cb)) == FALSE &&
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(file_duration_cb)) == FALSE) {
      if (tb == ring_filesize_cb)
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(file_duration_cb), TRUE);
      else
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ring_filesize_cb), TRUE);
    }

    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_lb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb)));

    /* The ring filesize spinbox is sensitive if the "Next capture file
         after N kilobytes" checkbox is on. */
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_filesize_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_cbx),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_filesize_cb)));

    /* The ring duration spinbox is sensitive if the "Next capture file
         after N seconds" checkbox is on. */
    gtk_widget_set_sensitive(GTK_WIDGET(file_duration_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(file_duration_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(file_duration_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(file_duration_cbx),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(file_duration_cb)));

    gtk_widget_set_sensitive(GTK_WIDGET(stop_filesize_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(stop_filesize_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(stop_filesize_cbx), FALSE);

    gtk_widget_set_sensitive(GTK_WIDGET(stop_files_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(stop_files_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_files_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(stop_files_lb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_files_cb)));
  } else {
    /* Ring buffer mode disabled. */
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_lb), FALSE);

    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_sb),FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_cbx),FALSE);

    gtk_widget_set_sensitive(GTK_WIDGET(file_duration_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(file_duration_sb),FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(file_duration_cbx),FALSE);

    /* The maximum file size spinbox is sensitive if the "Stop capture
         after N kilobytes" checkbox is on. */
    gtk_widget_set_sensitive(GTK_WIDGET(stop_filesize_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(stop_filesize_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_filesize_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(stop_filesize_cbx),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_filesize_cb)));

    gtk_widget_set_sensitive(GTK_WIDGET(stop_files_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(stop_files_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(stop_files_lb), FALSE);
  }

  /* The maximum packet count spinbox is sensitive if the "Stop capture
     after N packets" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(stop_packets_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_packets_cb)));
  gtk_widget_set_sensitive(GTK_WIDGET(stop_packets_lb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_packets_cb)));

  /* The capture duration spinbox is sensitive if the "Stop capture
     after N seconds" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(stop_duration_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_duration_cb)));
  gtk_widget_set_sensitive(GTK_WIDGET(stop_duration_cbx),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(stop_duration_cb)));
}

#endif /* HAVE_LIBPCAP */
