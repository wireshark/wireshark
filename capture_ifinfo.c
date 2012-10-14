/* capture_ifinfo.c
 * Routines for getting interface information from dumpcap
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>         /* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>           /* needed to define AF_ values on Windows */
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include <glib.h>

#include "capture_opts.h"
#include "capture_sync.h"
#include "log.h"

#include "wsutil/file_util.h"

#include "capture_ifinfo.h"

#ifdef HAVE_PCAP_REMOTE
static GList *remote_interface_list = NULL;

static void append_remote_list(GList *iflist)
{
    GSList *list;
    GList *rlist;
    if_addr_t *if_addr, *temp_addr;
    if_info_t *if_info, *temp;

    for (rlist = g_list_nth(remote_interface_list, 0); rlist != NULL; rlist = g_list_next(rlist)) {
        if_info = (if_info_t *)rlist->data;
        temp = g_malloc0(sizeof(if_info_t));
        temp->name = g_strdup(if_info->name);
        temp->description = g_strdup(if_info->description);
        for (list = g_slist_nth(if_info->addrs, 0); list != NULL; list = g_slist_next(list)) {
            temp_addr = g_malloc0(sizeof(if_addr_t));
            if_addr = (if_addr_t *)list->data;
            if (if_addr) {
                temp_addr->ifat_type = if_addr->ifat_type;
                if (temp_addr->ifat_type == IF_AT_IPv4) {
                    temp_addr->addr.ip4_addr = if_addr->addr.ip4_addr;
                } else {
                    memcpy(temp_addr->addr.ip6_addr, if_addr->addr.ip6_addr, sizeof(if_addr->addr));
                }
            } else {
                g_free(temp_addr);
                temp_addr = NULL;
            }
            if (temp_addr) {
                temp->addrs = g_slist_append(temp->addrs, temp_addr);
            }
        }
        temp->loopback = if_info->loopback;
        iflist = g_list_append(iflist, temp);
   }
}
#endif

/**
 * Fetch the interface list from a child process (dumpcap).
 *
 * @return A GList containing if_info_t structs if successful, NULL (with err and possibly err_str set) otherwise.
 *
 */

/* XXX - We parse simple text output to get our interface list.  Should
 * we use "real" data serialization instead, e.g. via XML? */
GList *
capture_interface_list(int *err, char **err_str)
{
    int        ret;
    GList     *if_list = NULL;
    int        i, j;
    gchar     *data, *primary_msg, *secondary_msg;
    gchar    **raw_list, **if_parts, **addr_parts;
    gchar     *name;
    if_info_t *if_info;
    if_addr_t *if_addr;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface List ...");

    /* Try to get our interface list */
    ret = sync_interface_list_open(&data, &primary_msg, &secondary_msg);
    if (ret != 0) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface List failed!");
        if (err_str) {
            *err_str = primary_msg;
        } else {
            g_free(primary_msg);
        }
        g_free(secondary_msg);
        *err = CANT_GET_INTERFACE_LIST;
        return NULL;
    }

    /* Split our lines */
#ifdef _WIN32
    raw_list = g_strsplit(data, "\r\n", 0);
#else
    raw_list = g_strsplit(data, "\n", 0);
#endif
    g_free(data);

    for (i = 0; raw_list[i] != NULL; i++) {
        if_parts = g_strsplit(raw_list[i], "\t", 4);
        if (if_parts[0] == NULL || if_parts[1] == NULL || if_parts[2] == NULL ||
                if_parts[3] == NULL) {
            g_strfreev(if_parts);
            continue;
        }

        /* Number followed by the name, e.g "1. eth0" */
        name = strchr(if_parts[0], ' ');
        if (name) {
            name++;
        } else {
            g_strfreev(if_parts);
            continue;
        }

        if_info = g_malloc0(sizeof(if_info_t));
        if_info->name = g_strdup(name);
        if (strlen(if_parts[1]) > 0)
            if_info->description = g_strdup(if_parts[1]);
        addr_parts = g_strsplit(if_parts[2], ",", 0);
        for (j = 0; addr_parts[j] != NULL; j++) {
            if_addr = g_malloc0(sizeof(if_addr_t));
            if (inet_pton(AF_INET, addr_parts[j], &if_addr->addr.ip4_addr)) {
                if_addr->ifat_type = IF_AT_IPv4;
            } else if (inet_pton(AF_INET6, addr_parts[j],
                    &if_addr->addr.ip6_addr)) {
                if_addr->ifat_type = IF_AT_IPv6;
            } else {
                g_free(if_addr);
                if_addr = NULL;
            }
            if (if_addr) {
                if_info->addrs = g_slist_append(if_info->addrs, if_addr);
            }
        }
        if (strcmp(if_parts[3], "loopback") == 0)
            if_info->loopback = TRUE;
        g_strfreev(if_parts);
        g_strfreev(addr_parts);
        if_list = g_list_append(if_list, if_info);
    }
    g_strfreev(raw_list);

    /* Check to see if we built a list */
    if (if_list == NULL) {
        *err = NO_INTERFACES_FOUND;
        if (err_str)
            *err_str = g_strdup("No interfaces found");
    }
#ifdef HAVE_PCAP_REMOTE
    if (remote_interface_list && g_list_length(remote_interface_list) > 0) {
        append_remote_list(if_list);
    }
#endif
    return if_list;
}

/* XXX - We parse simple text output to get our interface list.  Should
 * we use "real" data serialization instead, e.g. via XML? */
if_capabilities_t *
capture_get_if_capabilities(const gchar *ifname, gboolean monitor_mode,
                            char **err_str)
{
    if_capabilities_t *caps;
    GList              *linktype_list = NULL;
    int                 err, i;
    gchar              *data, *primary_msg, *secondary_msg;
    gchar             **raw_list, **lt_parts;
    data_link_info_t   *data_link_info;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities ...");

    /* Try to get our interface list */
    err = sync_if_capabilities_open(ifname, monitor_mode, &data,
                                    &primary_msg, &secondary_msg);
    if (err != 0) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities failed!");
        if (err_str) {
            *err_str = primary_msg;
        } else {
            g_free(primary_msg);
        }
        g_free(secondary_msg);
        return NULL;
    }

    /* Split our lines */
#ifdef _WIN32
    raw_list = g_strsplit(data, "\r\n", 0);
#else
    raw_list = g_strsplit(data, "\n", 0);
#endif
    g_free(data);

    /*
     * First line is 0 if monitor mode isn't supported, 1 if it is.
     */
    if (raw_list[0] == NULL || *raw_list[0] == '\0') {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities returned no information!");
        if (err_str) {
            *err_str = g_strdup("Dumpcap returned no interface capability information");
        }
        return NULL;
    }

    /*
     * Allocate the interface capabilities structure.
     */
    caps = g_malloc(sizeof *caps);
    switch (*raw_list[0]) {

    case '0':
        caps->can_set_rfmon = FALSE;
        break;

    case '1':
        caps->can_set_rfmon = TRUE;
        break;

    default:
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture Interface Capabilities returned bad information!");
        if (err_str) {
            *err_str = g_strdup_printf("Dumpcap returned \"%s\" for monitor-mode capability",
                                       raw_list[0]);
        }
        g_free(caps);
        return NULL;
    }

    /*
     * The rest are link-layer types.
     */
    for (i = 1; raw_list[i] != NULL; i++) {
        /* ...and what if the interface name has a tab in it, Mr. Clever Programmer? */
        lt_parts = g_strsplit(raw_list[i], "\t", 3);
        if (lt_parts[0] == NULL || lt_parts[1] == NULL || lt_parts[2] == NULL) {
            g_strfreev(lt_parts);
            continue;
        }

        data_link_info = g_malloc(sizeof (data_link_info_t));
        data_link_info->dlt = (int) strtol(lt_parts[0], NULL, 10);
        data_link_info->name = g_strdup(lt_parts[1]);
        if (strcmp(lt_parts[2], "(not supported)") != 0)
            data_link_info->description = g_strdup(lt_parts[2]);
        else
            data_link_info->description = NULL;

        linktype_list = g_list_append(linktype_list, data_link_info);
    }
    g_strfreev(raw_list);

    /* Check to see if we built a list */
    if (linktype_list == NULL) {
        /* No. */
        if (err_str)
            *err_str = g_strdup("Dumpcap returned no link-layer types");
        g_free(caps);
        return NULL;
    }
    caps->data_link_types = linktype_list;
    return caps;
}

#ifdef HAVE_PCAP_REMOTE
void add_interface_to_remote_list(if_info_t *if_info)
{
    GSList *list;
    if_addr_t *if_addr, *temp_addr;

    if_info_t *temp = g_malloc0(sizeof(if_info_t));
    temp->name = g_strdup(if_info->name);
    temp->description = g_strdup(if_info->description);
    for (list = g_slist_nth(if_info->addrs, 0); list != NULL; list = g_slist_next(list)) {
        temp_addr = g_malloc0(sizeof(if_addr_t));
        if_addr = (if_addr_t *)list->data;
        if (if_addr) {
            temp_addr->ifat_type = if_addr->ifat_type;
            if (temp_addr->ifat_type == IF_AT_IPv4) {
                temp_addr->addr.ip4_addr = if_addr->addr.ip4_addr;
            } else {
                memcpy(temp_addr->addr.ip6_addr, if_addr->addr.ip6_addr, sizeof(if_addr->addr));
            }
        } else {
            g_free(temp_addr);
            temp_addr = NULL;
        }
        if (temp_addr) {
            temp->addrs = g_slist_append(temp->addrs, temp_addr);
        }
    }
    temp->loopback = if_info->loopback;
    remote_interface_list = g_list_append(remote_interface_list, temp);
}
#endif

guint
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
     *    http://www.iana.org/assignments/ianaiftype-mib
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
        g_free(wireless_path);
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
#endif /* HAVE_LIBPCAP */
