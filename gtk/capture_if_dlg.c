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

#include <gtk/gtk.h>

#ifdef HAVE_LIBPCAP

#include <string.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <epan/prefs.h>

#include "../capture_errs.h"
#include "../capture_ifinfo.h"
#include "../simple_dialog.h"
#include "../capture.h"
#include "../capture-pcap-util.h"
#include "../capture_ui_utils.h"
#include "wsutil/file_util.h"
#include <wiretap/wtap.h>

#ifdef _WIN32
#include "../capture-wpcap.h"
#include "gtk/capture_if_details_dlg_win32.h"
#endif

#include "gtk/stock_icons.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#include "gtk/recent.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/main.h"
#include "gtk/main_toolbar.h"
#include "gtk/help_dlg.h"
#include "gtk/keys.h"
#include "gtk/webbrowser.h"
#include "gtk/capture_globals.h"
#include "gtk/network_icons.h"
#include "gtk/main_welcome.h"

#ifdef HAVE_AIRPCAP
#include "../image/toolbar/capture_airpcap_16.xpm"
#endif

#ifdef _WIN32
#include "../image/toolbar/capture_ethernet_16.xpm"
#include "../image/toolbar/modem_16.xpm"
#endif

#include "../image/toolbar/network_virtual_16.xpm"

/* new buttons to be used instead of labels for 'Capture','Prepare',' */
/*#include "../image/toolbar/capture_capture_16.xpm"*/
/*#include "../image/toolbar/capture_prepare_16.xpm"*/
/*#include "../image/toolbar/capture_details_16.xpm"*/


#ifdef HAVE_AIRPCAP
#include "airpcap.h"
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"
#include "airpcap_dlg.h"
#endif

#define CAPTURE_IF_IP_ADDR_LABEL      "capture_if_ip_addr_label"
#define CAPTURE_IF_SELECTED_IP_ADDR   "capture_if_selected_ip_addr"

/*
 * Keep a static pointer to the current "Capture Interfaces" window, if
 * any, so that if somebody tries to do "Capture:Start" while there's
 * already a "Capture Interfaces" window up, we just pop up the existing
 * one, rather than creating a new one.
 */
static GtkWidget *cap_if_w;

static GList     *if_data_list = NULL;

static guint      timer_id;

static GtkWidget *stop_bt, *capture_bt, *options_bt;

static GList     *if_list;

static guint   currently_selected = 0;
/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 */
#define	CAP_READ_TIMEOUT	250


/* the "runtime" data of one interface */
typedef struct if_dlg_data_s {
    GtkWidget   *device_lb;
    GtkWidget   *descr_lb;
    GtkWidget   *ip_lb;
    GtkWidget   *curr_lb;
    GtkWidget   *last_lb;
    GtkWidget   *choose_bt;
#ifdef _WIN32
    GtkWidget   *details_bt;
#endif
    guint32     last_packets;
    gchar       *device;
    if_info_t   if_info;
    gboolean    selected;
} if_dlg_data_t;

static gboolean gbl_capture_in_progress = FALSE;

void
update_selected_interface(gchar *name, gboolean activate)
{
  guint ifs;
  GList *curr;
  if_dlg_data_t *temp;

  for (ifs = 0; ifs < g_list_length(if_data_list); ifs++) {
    curr = g_list_nth(if_data_list, ifs);
    temp = (if_dlg_data_t *)(curr->data);
    if (strcmp(name, temp->if_info.name) == 0) {
      if (activate) {
        gtk_toggle_button_set_active((GtkToggleButton *)temp->choose_bt, TRUE);
      } else {
        gtk_toggle_button_set_active((GtkToggleButton *)temp->choose_bt, FALSE);
      }
      break;
    }
  }
}

static void
store_selected(GtkWidget *choose_bt, gpointer if_data)
{
  if_dlg_data_t *if_dlg_data = if_data, *temp;
  GList *curr;
  unsigned int ifs, i;
  gboolean found;
  cap_settings_t cap_settings;
  interface_options interface_opts;

  for (ifs = 0; ifs < g_list_length(if_data_list); ifs++) {
    curr = g_list_nth(if_data_list, ifs);
    temp = (if_dlg_data_t *)(curr->data);
    found = FALSE;
    if (strcmp(if_dlg_data->if_info.name, temp->if_info.name) == 0) {
      temp->selected ^=1;
      if_data_list = g_list_remove(if_data_list, curr->data);
      if_data_list = g_list_insert(if_data_list, temp, ifs);
      
      for (i = 0; i < global_capture_opts.ifaces->len; i++) {
        if (strcmp(g_array_index(global_capture_opts.ifaces, interface_options, i).name, temp->if_info.name) == 0) {
            found = TRUE;
          if (!temp->selected) {
            interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
            global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, i);
            if (gtk_widget_is_focus(choose_bt) && get_welcome_window()) {
              change_interface_selection(interface_opts.name, FALSE);
            }
            g_free(interface_opts.name);
            g_free(interface_opts.descr);
            g_free(interface_opts.cfilter);
#ifdef HAVE_PCAP_REMOTE
            g_free(interface_opts.remote_host);
            g_free(interface_opts.remote_port);
            g_free(interface_opts.auth_username);
            g_free(interface_opts.auth_password);
#endif
            break;
          }
        } 
      } 
      if (!found && temp->selected) {
        interface_opts.name = g_strdup(temp->if_info.name);
        interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
        interface_opts.linktype = capture_dev_user_linktype_find(interface_opts.name);
        interface_opts.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
        interface_opts.has_snaplen = global_capture_opts.default_options.has_snaplen;
        interface_opts.snaplen = global_capture_opts.default_options.snaplen;
        cap_settings = capture_get_cap_settings (interface_opts.name);;
        interface_opts.promisc_mode = global_capture_opts.default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        interface_opts.buffer_size =  global_capture_opts.default_options.buffer_size;
#endif
        interface_opts.monitor_mode = cap_settings.monitor_mode;
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
        g_array_append_val(global_capture_opts.ifaces, interface_opts);
        if (gtk_widget_is_focus(choose_bt) && get_welcome_window() != NULL) {
          change_interface_selection(g_strdup(temp->if_info.name), TRUE);
        }
      }
      
      if (temp->selected)
        currently_selected += 1;
      else
        currently_selected -= 1;
      break;
    }
  }
  if (cap_if_w) {
#ifdef USE_THREADS
    gtk_widget_set_sensitive(capture_bt, !gbl_capture_in_progress && (currently_selected > 0));
#else
    gtk_widget_set_sensitive(capture_bt, !gbl_capture_in_progress && (currently_selected == 1));
#endif
    gtk_widget_set_sensitive(options_bt, !gbl_capture_in_progress && (currently_selected <= 1));
  }
}

/* start capture button was pressed */
static void
#ifdef HAVE_AIRPCAP
capture_do_cb(GtkWidget *capture_bt _U_, gpointer if_data)
#else
capture_do_cb(GtkWidget *capture_bt _U_, gpointer if_data _U_)
#endif
{
  if_dlg_data_t *temp;
  GList *curr;
  int ifs;
#ifdef HAVE_AIRPCAP
  if_dlg_data_t *if_dlg_data = if_data;

  airpcap_if_active = get_airpcap_if_from_name(airpcap_if_list, if_dlg_data->if_info.name);
  airpcap_if_selected = airpcap_if_active;
#endif

  for (ifs = 0; (curr = g_list_nth(if_data_list, ifs)); ifs++) {
    temp = (if_dlg_data_t *)(curr->data);
    gtk_widget_set_sensitive(temp->choose_bt, FALSE);
  }

  /* XXX - remove this? */
  if (global_capture_opts.save_file) {
    g_free(global_capture_opts.save_file);
    global_capture_opts.save_file = NULL;
  }

  if (global_capture_opts.ifaces->len > 1) {
    global_capture_opts.use_pcapng = TRUE;
  }
  /* stop capturing from all interfaces, we are going to do real work now ... */
  window_destroy(cap_if_w);

  capture_start_cb(NULL, NULL);
}


/* prepare capture button was pressed */
static void
capture_prepare_cb(GtkWidget *prepare_bt _U_, gpointer if_data _U_)
{
  /* stop capturing from all interfaces, we are going to do real work now ... */
  window_destroy(cap_if_w);
  if (global_capture_opts.ifaces->len > 1) {
    global_capture_opts.use_pcapng = TRUE;
  }
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

/* update a single interface */
static void
update_if(if_dlg_data_t *if_dlg_data, if_stat_cache_t *sc)
{
  struct pcap_stat stats;
  gchar *str;
  guint diff;


  /*
   * Note that some versions of libpcap, on some versions of UN*X,
   * pcap_stats() returns the number of packets since the last
   * pcap_stats call.
   *
   * That's a bug, and should be fixed; "pcap_stats()" is supposed
   * to work the same way on all platforms.
   */
  if (sc) {
    if (capture_stats(sc, if_dlg_data->device, &stats)) {
      diff = stats.ps_recv - if_dlg_data->last_packets;
      if_dlg_data->last_packets = stats.ps_recv;

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

/* update all interfaces */
static gboolean
update_all(gpointer data)
{
    GList *curr;
    int ifs;
    if_stat_cache_t *sc = data;

    if (!cap_if_w) {
        return FALSE;
    }

    for (ifs = 0; (curr = g_list_nth(if_data_list, ifs)); ifs++) {
        update_if(curr->data, sc);
    }

    return TRUE;
}

/* a live capture has started or stopped */
void
set_capture_if_dialog_for_capture_in_progress(gboolean capture_in_progress)
{
  gbl_capture_in_progress = capture_in_progress;
  if (cap_if_w) {
    gtk_widget_set_sensitive(stop_bt, capture_in_progress);
#ifdef USE_THREADS
    gtk_widget_set_sensitive(capture_bt, !capture_in_progress && (currently_selected > 0));
#else
    gtk_widget_set_sensitive(capture_bt, !capture_in_progress && (currently_selected == 1));
#endif
    gtk_widget_set_sensitive(options_bt, !capture_in_progress && (currently_selected <= 1));
  }
}


/* the window was closed, cleanup things */
static void
capture_if_destroy_cb(GtkWidget *win _U_, gpointer user_data)
{
    GList *curr;
    int ifs;
    if_stat_cache_t *sc = user_data;

    g_source_remove(timer_id);

    for (ifs = 0; (curr = g_list_nth(if_data_list, ifs)); ifs++) {
        g_free(curr->data);
    }

    if_data_list = NULL;

    free_interface_list(if_list);

    /* Note that we no longer have a "Capture Options" dialog box. */
    cap_if_w = NULL;

    capture_stat_stop(sc);

#ifdef HAVE_AIRPCAP
    airpcap_set_toolbar_stop_capture(airpcap_if_active);
#endif
}


/*
 * Sorts the Interface List in alphabetical order
 */
gint if_list_comparator_alph (const void *first_arg, const void *second_arg){
  const if_info_t *first = first_arg, *second = second_arg;

  if (first != NULL && first->description != NULL &&
      second != NULL && second->description != NULL) {
    return g_ascii_strcasecmp(first->description, second->description);
  } else {
    return 0;
  }
}


/*
 * Used to retrieve the interface icon.
 * This is hideously platform-dependent.
 */
GtkWidget * capture_get_if_icon(const if_info_t* if_info)
{
#if defined(_WIN32)
  /*
   * Much digging failed to reveal any obvious way to get something such
   * as the SNMP MIB-II ifType value for an interface:
   *
   *	http://www.iana.org/assignments/ianaiftype-mib
   *
   * by making some NDIS request.
   */
  if ( if_info->description && ( strstr(if_info->description,"generic dialup") != NULL ||
       strstr(if_info->description,"PPP/SLIP") != NULL ) ) {
    return xpm_to_widget(modem_16_xpm);
  }

  if ( if_info->description && ( strstr(if_info->description,"Wireless") != NULL ||
       strstr(if_info->description,"802.11") != NULL || strstr(if_info->description,"AirPcap") != NULL ) ) {
    return pixbuf_to_widget(network_wireless_pb_data);
  }

  if ( strstr(if_info->name,"airpcap") != NULL ) {
    return pixbuf_to_widget(network_wireless_pb_data);
  }

  if ( if_info->description && strstr(if_info->description, "Bluetooth") != NULL ) {
    return pixbuf_to_widget(network_bluetooth_pb_data);
  }
#elif defined(__APPLE__)
  /*
   * XXX - yes, fetching all the network addresses for an interface
   * gets you an AF_LINK address, of type "struct sockaddr_dl", and,
   * yes, that includes an SNMP MIB-II ifType value.
   *
   * However, it's IFT_ETHER, i.e. Ethernet, for AirPort interfaces,
   * not IFT_IEEE80211 (which isn't defined in OS X in any case).
   *
   * Perhaps some other BSD-flavored OSes won't make this mistake;
   * however, FreeBSD 7.0 and OpenBSD 4.2, at least, appear to have
   * made the same mistake, at least for my Belkin ZyDAS stick.
   *
   * On Mac OS X, one might be able to get the information one wants from
   * IOKit.
   */
  if ( strcmp(if_info->name, "en1") == 0) {
    return pixbuf_to_widget(network_wireless_pb_data);
  }

  /*
   * XXX - PPP devices have names beginning with "ppp" and an IFT_ of
   * IFT_PPP, but they could be dial-up, or PPPoE, or mobile phone modem,
   * or VPN, or... devices.  One might have to dive into the bowels of
   * IOKit to find out.
   */

  /*
   * XXX - there's currently no support for raw Bluetooth capture,
   * and IP-over-Bluetooth devices just look like fake Ethernet
   * devices.  There's also Bluetooth modem support, but that'll
   * probably just give you a device that looks like a PPP device.
   */
#elif defined(__linux__)
  /*
   * Look for /sys/class/net/{device}/wireless.
   */
  ws_statb64 statb;
  char *wireless_path;

  wireless_path = g_strdup_printf("/sys/class/net/%s/wireless", if_info->name);
  if (wireless_path != NULL) {
    if (ws_stat64(wireless_path, &statb) == 0) {
      g_free(wireless_path);
      return pixbuf_to_widget(network_wireless_pb_data);
    }
    g_free(wireless_path);
  }

  /*
   * Bluetooth devices.
   *
   * XXX - this is for raw Bluetooth capture; what about IP-over-Bluetooth
   * devices?
   */
  if ( strstr(if_info->name,"bluetooth") != NULL) {
    return pixbuf_to_widget(network_bluetooth_pb_data);
  }

  /*
   * USB devices.
   */
  if ( strstr(if_info->name,"usbmon") != NULL ) {
    return pixbuf_to_widget(network_usb_pb_data);
  }
#endif

  /*
   * TODO: find a better icon!
   * Bridge, NAT, or host-only interfaces on VMWare hosts have the name
   * vmnet[0-9]+ or VMnet[0-9+ on Windows. Guests might use a native
   * (LANCE or E1000) driver or the vmxnet driver. These devices have an
   * IFT_ of IFT_ETHER, so we have to check the name.
   */
  if ( g_ascii_strncasecmp(if_info->name, "vmnet", 5) == 0) {
    return xpm_to_widget(network_virtual_16_xpm);
  }

  if ( g_ascii_strncasecmp(if_info->name, "vmxnet", 6) == 0) {
    return xpm_to_widget(network_virtual_16_xpm);
  }

  if ( if_info->description && strstr(if_info->description, "VMware") != NULL ) {
    return xpm_to_widget(network_virtual_16_xpm);
  }

  return pixbuf_to_widget(network_wired_pb_data);
}


static int
get_ip_addr_count(GSList *addr_list)
{
  GSList *curr_addr;
  if_addr_t *addr;
  int count;

  count = 0;
  for (curr_addr = addr_list; curr_addr != NULL;
       curr_addr = g_slist_next(curr_addr)) {
    addr = (if_addr_t *)curr_addr->data;
    switch (addr->ifat_type) {

    case IF_AT_IPv4:
    case IF_AT_IPv6:
      count++;
      break;

    default:
      /* In case we add non-IP addresses */
      break;
    }
  }
  return count;
}

static const gchar *
set_ip_addr_label(GSList *addr_list, GtkWidget *ip_lb, guint selected_ip_addr)
{
  GSList *curr_addr;
  if_addr_t *addr;
  const gchar *addr_str = NULL;

  curr_addr = g_slist_nth(addr_list, selected_ip_addr);
  if (curr_addr) {
    addr = (if_addr_t *)curr_addr->data;
    switch (addr->ifat_type) {

    case IF_AT_IPv4:
      addr_str = ip_to_str((guint8 *)&addr->addr.ip4_addr);
      break;

    case IF_AT_IPv6:
      addr_str = ip6_to_str((struct e_in6_addr *)&addr->addr.ip6_addr);
      break;

    default:
      /* Ignore non-IP addresses, in case we ever support them */
      break;
    }
  }

  if (addr_str) {
    gtk_label_set_text(GTK_LABEL(ip_lb), addr_str);
  } else {
    gtk_label_set_text(GTK_LABEL(ip_lb), "unknown");
  }
  g_object_set_data(G_OBJECT(ip_lb), CAPTURE_IF_SELECTED_IP_ADDR, GINT_TO_POINTER(selected_ip_addr));

  return addr_str;
}


static gboolean
ip_label_enter_cb(GtkWidget *eb, GdkEventCrossing *event _U_, gpointer user_data _U_)
{
    gtk_widget_set_state(eb, GTK_STATE_PRELIGHT);

    return FALSE;
}


static gboolean
ip_label_leave_cb(GtkWidget *eb, GdkEvent *event _U_, gpointer user_data _U_)
{
    gtk_widget_set_state(eb, GTK_STATE_NORMAL);

    return FALSE;
}


static gboolean
ip_label_press_cb(GtkWidget *widget, GdkEvent *event _U_, gpointer data)
{
  GtkWidget *ip_lb = g_object_get_data(G_OBJECT(widget), CAPTURE_IF_IP_ADDR_LABEL);
  GSList *addr_list = data;
  GSList *curr_addr, *start_addr;
  if_addr_t *addr;
  guint selected_ip_addr = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(ip_lb), CAPTURE_IF_SELECTED_IP_ADDR));

  /* Select next IP address */
  start_addr = g_slist_nth(addr_list, selected_ip_addr);
  for (;;) {
    selected_ip_addr++;
    if (g_slist_length(addr_list) <= selected_ip_addr) {
      /* Wrap around */
      selected_ip_addr = 0;
    }
    curr_addr = g_slist_nth(addr_list, selected_ip_addr);
    if (curr_addr == start_addr) {
      /* We wrapped all the way around */
      break;
    }

    addr = (if_addr_t *)curr_addr->data;
    switch (addr->ifat_type) {

    case IF_AT_IPv4:
    case IF_AT_IPv6:
      goto found;

    default:
      /* In case we add non-IP addresses */
      break;
    }
  }

found:
  set_ip_addr_label(addr_list, ip_lb, selected_ip_addr);

  return FALSE;
}

static void
capture_if_stop_cb(GtkWidget *w _U_, gpointer d _U_)
{
    guint ifs;
    GList *curr;
    if_dlg_data_t *if_data;

    for (ifs = 0; ifs < g_list_length(if_data_list); ifs++) {
        curr = g_list_nth(if_data_list, ifs);
        if_data = (if_dlg_data_t *)(curr->data);
        gtk_widget_set_sensitive(if_data->choose_bt, TRUE);
    }
    capture_stop_cb(NULL, NULL);
}


/* start getting capture stats from all interfaces */
void
capture_if_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget         *main_vb,
                    *main_sw,
                    *bbox,
                    *close_bt,
                    *help_bt,
                    *icon;

#ifdef HAVE_AIRPCAP
  GtkWidget         *decryption_cb;
#endif

  GtkWidget         *if_tb;
  GtkWidget         *if_lb;
  GtkWidget         *eb;
  int               err;
  gchar             *err_str;
  GtkRequisition    requisition;
  int               row, height;
  if_dlg_data_t     *if_dlg_data = NULL;
  int               ifs;
  GList             *curr;
  if_info_t         *if_info;
  GString           *if_tool_str = g_string_new("");
  const gchar       *addr_str;
  gchar             *user_descr;
  if_stat_cache_t   *sc;
  int               preselected = 0, i;
  interface_options interface_opts;
  gboolean      found = FALSE;

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
  preselected = global_capture_opts.ifaces->len;
  /* LOAD THE INTERFACES */
  if_list = capture_interface_list(&err, &err_str);
  if_list = g_list_sort (if_list, if_list_comparator_alph);
  if (if_list == NULL) {
    switch (err) {

    case CANT_GET_INTERFACE_LIST:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
      g_free(err_str);
      break;

    case NO_INTERFACES_FOUND:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "There are no interfaces on which a capture can be done.");
      break;
    }
    return;
  }

#ifdef HAVE_AIRPCAP
  /* LOAD AIRPCAP INTERFACES */
  airpcap_if_list = get_airpcap_interface_list(&err, &err_str);
  if (airpcap_if_list == NULL)
    airpcap_if_active = airpcap_if_selected = NULL;

  decryption_cb = g_object_get_data(G_OBJECT(airpcap_tb),AIRPCAP_TOOLBAR_DECRYPTION_KEY);
  update_decryption_mode_list(decryption_cb);

  if (airpcap_if_list == NULL && err == CANT_GET_AIRPCAP_INTERFACE_LIST) {
#if 0
    /* XXX - Do we need to show an error here? */
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
#endif
    g_free(err_str);
  }

  /* If no airpcap interface is present, gray everything */
  if (airpcap_if_active == NULL) {
    if (airpcap_if_list == NULL) {
      /*No airpcap device found */
      airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
    } else {
      /* default adapter is not airpcap... or is airpcap but is not found*/
      airpcap_set_toolbar_stop_capture(airpcap_if_active);
      airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
    }
  }

  airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif

  cap_if_w = dlg_window_new("Wireshark: Capture Interfaces");  /* transient_for top_level */
  gtk_window_set_destroy_with_parent (GTK_WINDOW(cap_if_w), TRUE);

  main_sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(main_sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(cap_if_w), main_sw);

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
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
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 1, 4, row, row+1);
#endif
  if_lb = gtk_label_new("Description");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 4, 5, row, row+1);

  if_lb = gtk_label_new(" IP ");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 5, 6, row, row+1);

  if_lb = gtk_label_new("Packets");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 6, 7, row, row+1);

  if_lb = gtk_label_new(" Packets/s ");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 7, 8, row, row+1);
  row++;

  height += 30;
  /* Start gathering statistics (using dumpcap) */
  sc = capture_stat_start(if_list);

  /* List the interfaces */
  currently_selected = 0;
  for (ifs = 0; (curr = g_list_nth(if_list, ifs)); ifs++) {
      g_string_assign(if_tool_str, "");
      if_info = curr->data;

      /* Continue if capture device is hidden */
      if (prefs_is_capture_device_hidden(if_info->name)) {
          continue;
      }

      if_dlg_data = g_malloc0(sizeof(if_dlg_data_t));

      if (preselected > 0) {
        found = FALSE;
        for (i = 0; i < (gint)global_capture_opts.ifaces->len; i++) {
          interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
          if ((interface_opts.name == NULL) ||
              (strcmp(interface_opts.name, (char*)if_info->name) != 0))
            continue;
          else {
            found = TRUE;
            currently_selected++;
            preselected--;
            break;
          }
        }
        if_dlg_data->selected = found;
      }
      else
        if_dlg_data->selected = FALSE;

      if_dlg_data->if_info = *if_info;

      if_dlg_data->choose_bt = gtk_check_button_new();
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->choose_bt, 0, 1, row, row+1);
      if (gbl_capture_in_progress) {
          gtk_widget_set_sensitive(if_dlg_data->choose_bt, FALSE);
      } else {
          gtk_widget_set_sensitive(if_dlg_data->choose_bt, TRUE);
      }
      gtk_toggle_button_set_active((GtkToggleButton *)if_dlg_data->choose_bt, if_dlg_data->selected);
      g_signal_connect(if_dlg_data->choose_bt, "toggled", G_CALLBACK(store_selected), if_dlg_data);
     /* Kind of adaptor (icon) */
#ifdef HAVE_AIRPCAP
      if (get_airpcap_if_from_name(airpcap_if_list,if_info->name) != NULL)
        icon = xpm_to_widget(capture_airpcap_16_xpm);
      else
        icon = capture_get_if_icon(if_info);
#else
      icon = capture_get_if_icon(if_info);
#endif

      gtk_table_attach_defaults(GTK_TABLE(if_tb), icon, 1, 2, row, row+1);

      /* device name */
      if_dlg_data->device_lb = gtk_label_new(if_info->name);
      if_dlg_data->device = if_info->name;
#ifndef _WIN32
      gtk_misc_set_alignment(GTK_MISC(if_dlg_data->device_lb), 0.0f, 0.5f);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->device_lb, 2, 4, row, row+1);
#endif
      g_string_append(if_tool_str, "Device: ");
      g_string_append(if_tool_str, if_info->name);
      g_string_append(if_tool_str, "\n");

      /* description */
      user_descr = capture_dev_user_descr_find(if_info->name);
      if (user_descr) {
        if_dlg_data->descr_lb = gtk_label_new(user_descr);
        g_free (user_descr);
      } else {
        if (if_info->description)
          if_dlg_data->descr_lb = gtk_label_new(if_info->description);
        else
          if_dlg_data->descr_lb = gtk_label_new("");
      }
      gtk_misc_set_alignment(GTK_MISC(if_dlg_data->descr_lb), 0.0f, 0.5f);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->descr_lb, 4, 5, row, row+1);

      if (if_info->description) {
        g_string_append(if_tool_str, "Description: ");
        g_string_append(if_tool_str, if_info->description);
        g_string_append(if_tool_str, "\n");
      }

      /* IP address */
      /* Only one IP address will be shown, start with the first */
      g_string_append(if_tool_str, "IP: ");
      if_dlg_data->ip_lb = gtk_label_new("");
      addr_str = set_ip_addr_label (if_info->addrs, if_dlg_data->ip_lb, 0);
      if (addr_str) {
        gtk_widget_set_sensitive(if_dlg_data->ip_lb, TRUE);
        g_string_append(if_tool_str, addr_str);
      } else {
        gtk_widget_set_sensitive(if_dlg_data->ip_lb, FALSE);
        g_string_append(if_tool_str, "unknown");
      }
      eb = gtk_event_box_new ();
      gtk_container_add(GTK_CONTAINER(eb), if_dlg_data->ip_lb);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), eb, 5, 6, row, row+1);
      if (get_ip_addr_count(if_info->addrs) > 1) {
        /* More than one IP address, make it possible to toggle */
        g_object_set_data(G_OBJECT(eb), CAPTURE_IF_IP_ADDR_LABEL, if_dlg_data->ip_lb);
        g_signal_connect(eb, "enter-notify-event", G_CALLBACK(ip_label_enter_cb), NULL);
        g_signal_connect(eb, "leave-notify-event", G_CALLBACK(ip_label_leave_cb), NULL);
        g_signal_connect(eb, "button-press-event", G_CALLBACK(ip_label_press_cb), if_info->addrs);
      }
      g_string_append(if_tool_str, "\n");

      /* packets */
      if_dlg_data->curr_lb = gtk_label_new("-");
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->curr_lb, 6, 7, row, row+1);

      /* packets/s */
      if_dlg_data->last_lb = gtk_label_new("-");
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->last_lb, 7, 8, row, row+1);

      /* details button */
#ifdef _WIN32
      if_dlg_data->details_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_CAPTURE_DETAILS);
      gtk_widget_set_tooltip_text(if_dlg_data->details_bt, "Open the capture details dialog of this interface.");
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->details_bt, 8, 9, row, row+1);
      if (capture_if_has_details(if_dlg_data->device)) {
        g_signal_connect(if_dlg_data->details_bt, "clicked", G_CALLBACK(capture_details_cb), if_dlg_data);
      } else {
        gtk_widget_set_sensitive(if_dlg_data->details_bt, FALSE);
      }
#endif

      if_data_list = g_list_append(if_data_list, if_dlg_data);

      row++;
      if (row <= 10) {
        /* Lets add up 10 rows of interfaces, otherwise the window may become too high */
        gtk_widget_size_request(GTK_WIDGET(if_dlg_data->choose_bt), &requisition);
        height += requisition.height;
      }
  }

  g_string_free(if_tool_str, TRUE);

  /* Button row: close, help, stop, start, and options button */
  bbox = dlg_button_row_new(GTK_STOCK_HELP, WIRESHARK_STOCK_CAPTURE_START, WIRESHARK_STOCK_CAPTURE_OPTIONS, WIRESHARK_STOCK_CAPTURE_STOP, GTK_STOCK_CLOSE, NULL);

  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);
  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)(HELP_CAPTURE_INTERFACES_DIALOG));

  stop_bt = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CAPTURE_STOP);
  g_signal_connect(stop_bt, "clicked", G_CALLBACK(capture_if_stop_cb), NULL);
  close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
  window_set_cancel_button(cap_if_w, close_bt, window_cancel_button_cb);
  gtk_widget_set_tooltip_text(close_bt, "Close this window.");
  options_bt = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CAPTURE_OPTIONS);
  g_signal_connect(options_bt, "clicked", G_CALLBACK(capture_prepare_cb), if_dlg_data);
  capture_bt = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CAPTURE_START);
  g_signal_connect(capture_bt, "clicked", G_CALLBACK(capture_do_cb), if_dlg_data);
  gtk_widget_size_request(GTK_WIDGET(close_bt), &requisition);
  /* height + static offset + what the GTK MS Windows Engine needs in addition per interface */
  height += requisition.height + 20 + ifs;
  gtk_window_set_default_size(GTK_WINDOW(cap_if_w), -1, height);

  gtk_widget_grab_default(close_bt);

  g_signal_connect(cap_if_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(cap_if_w, "destroy", G_CALLBACK(capture_if_destroy_cb), sc);

  gtk_widget_show_all(cap_if_w);
  window_present(cap_if_w);

  set_capture_if_dialog_for_capture_in_progress(gbl_capture_in_progress);

    /* update the interface list every 1000ms */
  timer_id = g_timeout_add(1000, update_all, sc);
}

GtkWidget* get_interfaces_dialog_window(void)
{
  return cap_if_w;
}
#else /* HAVE_LIBPCAP */

void
set_capture_if_dialog_for_capture_in_progress(gboolean capture_in_progress _U_)
{
}

#endif /* HAVE_LIBPCAP */
