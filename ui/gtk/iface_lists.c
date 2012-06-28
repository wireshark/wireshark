/* iface_lists.c
 * Code to manage the global list of interfaces and to update widgets/windows
 * displaying items from those lists
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

#include <string.h>

#include <glib.h>

#include <epan/prefs.h>
#include <epan/to_str.h>

#include "../capture_ui_utils.h"

#include "ui/gtk/capture_dlg.h"
#include "ui/gtk/capture_if_dlg.h"
#include "ui/gtk/capture_globals.h"
#include "ui/gtk/main_welcome.h"

#include "ui/gtk/iface_lists.h"

capture_options global_capture_opts;

static guint
get_interface_type(gchar *name, gchar *description)
{
#if defined(__linux__)
    ws_statb64 statb;
    char *wireless_path;
#endif
#if defined(_WIN32)
    /*
     * Much digging failed to reveal any obvious way to get something such
     * as the SNMP MIB-II ifType value for an interface:
     *
     *	http://www.iana.org/assignments/ianaiftype-mib
     *
     * by making some NDIS request.
     */
    if (description && (strstr(description,"generic dialup") != NULL ||
            strstr(description,"PPP/SLIP") != NULL )) {
        return IF_DIALUP;
    } else if (description && (strstr(description,"Wireless") != NULL ||
            strstr(description,"802.11") != NULL)) {
        return IF_WIRELESS;
    } else if (description && strstr(description,"AirPcap") != NULL ||
            strstr(name,"airpcap")) {
        return IF_AIRPCAP;
    } else if (description && strstr(description, "Bluetooth") != NULL ) {
        return IF_BLUETOOTH;
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
     * XXX - this is wrong on a MacBook Air, as en0 is the AirPort
     * interface, and it's also wrong on a Mac that has no AirPort
     * interfaces and has multiple Ethernet interfaces.
     *
     * The SystemConfiguration framework is your friend here.
     * SCNetworkInterfaceGetInterfaceType() will get the interface
     * type.  SCNetworkInterfaceCopyAll() gets all network-capable
     * interfaces on the system; SCNetworkInterfaceGetBSDName()
     * gets the "BSD name" of the interface, so we look for
     * an interface with the specified "BSD name" and get its
     * interface type.  The interface type is a CFString, and:
     *
     *    kSCNetworkInterfaceTypeIEEE80211 means IF_WIRELESS;
     *    kSCNetworkInterfaceTypeBluetooth means IF_BLUETOOTH;
     *    kSCNetworkInterfaceTypeModem or
     *    kSCNetworkInterfaceTypePPP or
     *    maybe kSCNetworkInterfaceTypeWWAN means IF_DIALUP
     */
    if (strcmp(name, "en1") == 0) {
        return IF_WIRELESS;
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
    wireless_path = g_strdup_printf("/sys/class/net/%s/wireless", name);
    if (wireless_path != NULL) {
        if (ws_stat64(wireless_path, &statb) == 0) {
            g_free(wireless_path);
            return IF_WIRELESS;
        }
    }
    /*
     * Bluetooth devices.
     *
     * XXX - this is for raw Bluetooth capture; what about IP-over-Bluetooth
     * devices?
     */
    if ( strstr(name,"bluetooth") != NULL) {
        return IF_BLUETOOTH;
    }

    /*
     * USB devices.
     */
    if ( strstr(name,"usbmon") != NULL ) {
        return IF_USB;
    }
#endif
    /*
     * Bridge, NAT, or host-only interfaces on VMWare hosts have the name
     * vmnet[0-9]+ or VMnet[0-9+ on Windows. Guests might use a native
     * (LANCE or E1000) driver or the vmxnet driver. These devices have an
     * IFT_ of IFT_ETHER, so we have to check the name.
     */
    if ( g_ascii_strncasecmp(name, "vmnet", 5) == 0) {
        return IF_VIRTUAL;
    }

    if ( g_ascii_strncasecmp(name, "vmxnet", 6) == 0) {
        return IF_VIRTUAL;
    }

    if (description && strstr(description, "VMware") != NULL ) {
        return IF_VIRTUAL;
    }

    return IF_WIRED;
}

/*
 * Fetch the list of local interfaces with capture_interface_list()
 * and set the list of "all interfaces" in *capture_opts to include
 * those interfaces.
 */
static void
scan_local_interfaces(capture_options* capture_opts)
{
    GList             *if_entry, *lt_entry, *if_list;
    if_info_t         *if_info, *temp;
    char              *if_string;
    gchar             *descr;
    if_capabilities_t *caps=NULL;
    gint              linktype_count;
    cap_settings_t    cap_settings;
    GSList            *curr_addr;
    int               ips = 0, i, err;
    guint             count = 0, j;
    if_addr_t         *addr, *temp_addr;
    link_row          *link = NULL;
    data_link_info_t  *data_link_info;
    interface_t       device;
    GString           *ip_str;
    interface_options interface_opts;
    gboolean          found = FALSE;
    

    if (capture_opts->all_ifaces->len > 0) {
        for (i = (int)capture_opts->all_ifaces->len-1; i >= 0; i--) {
            device = g_array_index(capture_opts->all_ifaces, interface_t, i);
            if (device.local) {
                capture_opts->all_ifaces = g_array_remove_index(capture_opts->all_ifaces, i);
            }
        }
    }
    /* Scan through the list and build a list of strings to display. */
    if_list = capture_interface_list(&err, NULL);
    count = 0;
    for (if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
        if_info = if_entry->data;
        ip_str = g_string_new("");
        ips = 0;
        if (strstr(if_info->name, "rpcap:")) {
            continue;
        }
        device.name = g_strdup(if_info->name);
        device.hidden = FALSE;
        device.locked = FALSE;
        temp = g_malloc0(sizeof(if_info_t));
        temp->name = g_strdup(if_info->name);
        temp->description = g_strdup(if_info->description);
        temp->loopback = if_info->loopback;
        /* Is this interface hidden and, if so, should we include it anyway? */

        /* Do we have a user-supplied description? */
        descr = capture_dev_user_descr_find(if_info->name);
        if (descr != NULL) {
            /* Yes, we have a user-supplied description; use it. */
            if_string = g_strdup_printf("%s: %s", descr, if_info->name);
            g_free(descr);
        } else {
            /* No, we don't have a user-supplied description; did we get
            one from the OS or libpcap? */
            if (if_info->description != NULL) {
                /* Yes - use it. */
                if_string = g_strdup_printf("%s: %s", if_info->description, if_info->name);
            } else {
                /* No. */
                if_string = g_strdup(if_info->name);
            }
        }
        if (if_info->loopback) {
            device.display_name = g_strdup_printf("%s (loopback)", if_string);
        } else {
            device.display_name = g_strdup(if_string);
        }
        g_free(if_string);
        device.selected = FALSE;
        if (prefs_is_capture_device_hidden(if_info->name)) {
            device.hidden = TRUE;
        } 
        device.type = get_interface_type(if_info->name, if_info->description);
        cap_settings = capture_get_cap_settings(if_info->name);
        caps = capture_get_if_capabilities(if_info->name, cap_settings.monitor_mode, NULL);
        for (; (curr_addr = g_slist_nth(if_info->addrs, ips)) != NULL; ips++) {
            temp_addr = g_malloc0(sizeof(if_addr_t));
            if (ips != 0) {
                g_string_append(ip_str, "\n");
            }
            addr = (if_addr_t *)curr_addr->data;
            if (addr) {
                temp_addr->ifat_type = addr->ifat_type;
                switch (addr->ifat_type) {
                    case IF_AT_IPv4:
                        temp_addr->addr.ip4_addr = addr->addr.ip4_addr;
                        g_string_append(ip_str, ip_to_str((guint8 *)&addr->addr.ip4_addr));
                        break;
                    case IF_AT_IPv6:
                        memcpy(temp_addr->addr.ip6_addr, addr->addr.ip6_addr, sizeof(addr->addr));
                        g_string_append(ip_str,  ip6_to_str((struct e_in6_addr *)&addr->addr.ip6_addr));
                        break;
                    default:
                        /* In case we add non-IP addresses */
                        break;
                }
            } else {
                g_free(temp_addr);
                temp_addr = NULL;
            }
            if (temp_addr) {
                temp->addrs = g_slist_append(temp->addrs, temp_addr);
            }
        }
#ifdef HAVE_PCAP_REMOTE
        device.local = TRUE;
        device.remote_opts.src_type = CAPTURE_IFLOCAL;
        device.remote_opts.remote_host_opts.remote_host = g_strdup(capture_opts->default_options.remote_host);
        device.remote_opts.remote_host_opts.remote_port = g_strdup(capture_opts->default_options.remote_port);
        device.remote_opts.remote_host_opts.auth_type = capture_opts->default_options.auth_type;
        device.remote_opts.remote_host_opts.auth_username = g_strdup(capture_opts->default_options.auth_username);
        device.remote_opts.remote_host_opts.auth_password = g_strdup(capture_opts->default_options.auth_password);
        device.remote_opts.remote_host_opts.datatx_udp = capture_opts->default_options.datatx_udp;
        device.remote_opts.remote_host_opts.nocap_rpcap = capture_opts->default_options.nocap_rpcap;
        device.remote_opts.remote_host_opts.nocap_local = capture_opts->default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
        device.remote_opts.sampling_method = capture_opts->default_options.sampling_method;
        device.remote_opts.sampling_param  = capture_opts->default_options.sampling_param;	
#endif
        linktype_count = 0;
        device.links = NULL;
        if (caps != NULL) {
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = cap_settings.monitor_mode;
            device.monitor_mode_supported = caps->can_set_rfmon;
#endif 
            for (lt_entry = caps->data_link_types; lt_entry != NULL; lt_entry = g_list_next(lt_entry)) {
                data_link_info = lt_entry->data;
                if (linktype_count == 0) {
                    device.active_dlt = data_link_info->dlt;
                }
                link = (link_row *)g_malloc(sizeof(link_row));
                if (data_link_info->description != NULL) {
                    link->dlt = data_link_info->dlt;
                    link->name = g_strdup_printf("%s", data_link_info->description);
                } else {
                    link->dlt = -1;
                    link->name = g_strdup_printf("%s (not supported)", data_link_info->name);
                }
                device.links = g_list_append(device.links, link);
                linktype_count++;
            }
        } else {
            cap_settings.monitor_mode = FALSE;
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = FALSE;
            device.monitor_mode_supported = FALSE;
#endif
            device.active_dlt = -1;
        }
        device.addresses = g_strdup(ip_str->str);
        device.no_addresses = ips;
        device.local = TRUE;
        device.if_info = *temp;
        device.last_packets = 0;
        device.pmode        = capture_opts->default_options.promisc_mode;
        device.has_snaplen  = capture_opts->default_options.has_snaplen;
        device.snaplen      = capture_opts->default_options.snaplen;
        device.cfilter      = g_strdup(capture_opts->default_options.cfilter);
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        device.buffer = 1;
#endif
        
        if (capture_opts->ifaces->len > 0) {
            for (j = 0; j < capture_opts->ifaces->len; j++) {
                interface_opts = g_array_index(capture_opts->ifaces, interface_options, j);
                if (strcmp(interface_opts.name, device.name) == 0) {                   
#if defined(HAVE_PCAP_CREATE)
                    device.buffer = interface_opts.buffer_size;
                    device.monitor_mode_enabled = interface_opts.monitor_mode;
#endif
                    device.pmode = interface_opts.promisc_mode;
                    device.has_snaplen = interface_opts.has_snaplen;
                    device.snaplen = interface_opts.snaplen; 
                    device.cfilter = g_strdup(interface_opts.cfilter);
                    device.active_dlt = interface_opts.linktype;
                    device.selected = TRUE;
                    capture_opts->num_selected++;
                    break;
                }
            }
        }
        if (capture_opts->all_ifaces->len <= count) {
            g_array_append_val(capture_opts->all_ifaces, device);
            count = capture_opts->all_ifaces->len;
        } else {
            g_array_insert_val(capture_opts->all_ifaces, count, device);
        }
        if (caps != NULL) {
            free_if_capabilities(caps);
        }
            
        g_string_free(ip_str, TRUE);
        count++;
    }
    free_interface_list(if_list);
    /* see whether there are additional interfaces in ifaces */
    for (j = 0; j < capture_opts->ifaces->len; j++) {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, j);
        found = FALSE;
        for (i = 0; i < (int)capture_opts->all_ifaces->len; i++) {
            device = g_array_index(capture_opts->all_ifaces, interface_t, i);
            if (strcmp(device.name, interface_opts.name) == 0) {
                found = TRUE;
                break;
            }
        }
        if (!found) {  /* new interface, maybe a pipe */
            device.name         = g_strdup(interface_opts.name);
            device.display_name = g_strdup_printf("%s", device.name);
            device.hidden       = FALSE;
            device.selected     = TRUE;
            device.type         = IF_PIPE;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
            device.buffer = interface_opts.buffer_size;
#endif
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = interface_opts.monitor_mode;
            device.monitor_mode_supported = FALSE;
#endif
            device.pmode = interface_opts.promisc_mode;
            device.has_snaplen = interface_opts.has_snaplen;
            device.snaplen = interface_opts.snaplen; 
            device.cfilter = g_strdup(interface_opts.cfilter);
            device.active_dlt = interface_opts.linktype;
            device.addresses    = NULL;
            device.no_addresses = 0;
            device.last_packets = 0;
            device.links        = NULL;
            device.local        = TRUE;
            device.locked       = FALSE;

            g_array_append_val(capture_opts->all_ifaces, device);
            capture_opts->num_selected++;
        }
    }
}

/*
 * Get the global interface list.  Generate it if we haven't
 * done so already.
 */
void
fill_in_local_interfaces(capture_options* capture_opts)
{
    static gboolean initialized = FALSE;

    if (!initialized) {
        scan_local_interfaces(capture_opts);
        initialized = TRUE;
    }
}

/*
 * Refresh everything visible that shows an interface list that
 * includes local interfaces.
 */
void
refresh_local_interface_lists(void)
{
  /* Reload the local interface list. */
  scan_local_interfaces(&global_capture_opts);

  /* If there's an interfaces dialog up, refresh it. */
  if (interfaces_dialog_window_present())
    refresh_if_window();

  /* If there's a capture options dialog up, refresh it. */
  if (capture_dlg_window_present())
    capture_dlg_refresh_if();

  /* If the welcome screen is up, refresh its interface list. */
  if (get_welcome_window() != NULL)
    welcome_if_panel_reload();
}

/*
 * Refresh everything visible that shows an interface list that
 * includes non-local interfaces.
 */
void
refresh_non_local_interface_lists(void)
{
  /* If there's a capture options dialog up, refresh it. */
  if (capture_dlg_window_present())
    capture_dlg_refresh_if();

  /* If the welcome screen is up, refresh its interface list. */
  if (get_welcome_window() != NULL)
    welcome_if_panel_reload();
}

void
hide_interface(gchar* new_hide)
{
    gchar       *tok;
    guint       i;
    interface_t device;
    gboolean    found = FALSE;
    GList       *hidden_devices = NULL, *entry;
    if (new_hide != NULL) {
        for (tok = strtok (new_hide, ","); tok; tok = strtok(NULL, ",")) {
            hidden_devices = g_list_append(hidden_devices, tok);
        }
    }
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        found = FALSE;
        for (entry = hidden_devices; entry != NULL; entry = g_list_next(entry)) {
            if (strcmp(entry->data, device.name)==0) {
                device.hidden = TRUE;
                if (device.selected) {
                    device.selected = FALSE;
                    global_capture_opts.num_selected--;
                }
                found = TRUE;
                break;
            }
        } 
        if (!found) {
            device.hidden = FALSE;
        }
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        g_array_insert_val(global_capture_opts.all_ifaces, i, device);
    }
}
#endif /* HAVE_LIBPCAP */
