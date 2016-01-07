/* capture-pcap-util.c
 * Utility routines for packet capture
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

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

/*
 * Linux bonding devices mishandle unknown ioctls; they fail
 * with ENODEV rather than ENOTSUP, EOPNOTSUPP, or ENOTTY,
 * so pcap_can_set_rfmon() returns a "no such device" indication
 * if we try to do SIOCGIWMODE on them.
 *
 * So, on Linux, we check for bonding devices, if we can, before
 * trying pcap_can_set_rfmon(), as pcap_can_set_rfmon() will
 * end up trying SIOCGIWMODE on the device if that ioctl exists.
 */
#if defined(HAVE_PCAP_CREATE) && defined(__linux__)

#include <sys/ioctl.h>

/*
 * If we're building for a Linux version that supports bonding,
 * HAVE_BONDING will be defined.
 */

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_LINUX_IF_BONDING_H
#include <linux/if_bonding.h>
#endif

#if defined(BOND_INFO_QUERY_OLD) || defined(SIOCBONDINFOQUERY)
#define HAVE_BONDING
#endif

#endif /* defined(HAVE_PCAP_CREATE) && defined(__linux__) */

#include "caputils/capture_ifinfo.h"
#include "caputils/capture-pcap-util.h"
#include "caputils/capture-pcap-util-int.h"

#include "log.h"

#include <wsutil/file_util.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif

#ifdef _WIN32
#include "caputils/capture_win_ifnames.h" /* windows friendly interface names */
#endif

/*
 * Standard secondary message for unexpected errors.
 */
static const char please_report[] =
    "Please report this to the Wireshark developers.\n"
    "https://bugs.wireshark.org/\n"
    "(This is not a crash; please do not report it as such.)";

/*
 * Given an interface name, find the "friendly name" and interface
 * type for the interface.
 */

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <wsutil/cfutils.h>

/*
 * On OS X, we get the "friendly name" and interface type for the interface
 * from the System Configuration framework.
 *
 * To find the System Configuration framework information for the
 * interface, we get all the interfaces that the System Configuration
 * framework knows about and look for the one with a "BSD name" matching
 * the interface name.
 *
 * If we find it, we use its "localized display name", if it has one, as
 * the "friendly name".
 *
 * As for the interface type:
 *
 * Yes, fetching all the network addresses for an interface gets you an
 * AF_LINK address, of type "struct sockaddr_dl", and, yes, that includes
 * an SNMP MIB-II ifType value.
 *
 * However, it's IFT_ETHER, i.e. Ethernet, for AirPort interfaces,
 * not IFT_IEEE80211 (which isn't defined in OS X in any case).
 *
 * Perhaps some other BSD-flavored OSes won't make this mistake;
 * however, FreeBSD 7.0 and OpenBSD 4.2, at least, appear to have
 * made the same mistake, at least for my Belkin ZyDAS stick.
 *
 * SCNetworkInterfaceGetInterfaceType() will get the interface
 * type.  The interface type is a CFString, and:
 *
 *    kSCNetworkInterfaceTypeIEEE80211 means IF_WIRELESS;
 *    kSCNetworkInterfaceTypeBluetooth means IF_BLUETOOTH;
 *    kSCNetworkInterfaceTypeModem or
 *    kSCNetworkInterfaceTypePPP or
 *    maybe kSCNetworkInterfaceTypeWWAN means IF_DIALUP
 */
static void
add_unix_interface_ifinfo(if_info_t *if_info, const char *name,
			  const char *description _U_)
{
	CFStringRef name_CFString;
	CFArrayRef interfaces;
	CFIndex num_interfaces;
	CFIndex i;
	SCNetworkInterfaceRef interface;
	CFStringRef bsdname_CFString;
	CFStringRef friendly_name_CFString;
	CFStringRef interface_type_CFString;

	interfaces = SCNetworkInterfaceCopyAll();
	if (interfaces == NULL) {
		/*
		 * Couldn't get a list of interfaces.
		 */
		return;
	}

	name_CFString = CFStringCreateWithCString(kCFAllocatorDefault,
	    name, kCFStringEncodingUTF8);
	if (name_CFString == NULL) {
		/*
		 * Couldn't convert the interface name to a CFString.
		 */
		CFRelease(interfaces);
		return;
	}

	num_interfaces = CFArrayGetCount(interfaces);
	for (i = 0; i < num_interfaces; i++) {
		interface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces, i);
		bsdname_CFString = SCNetworkInterfaceGetBSDName(interface);
		if (bsdname_CFString == NULL) {
			/*
			 * This interface has no BSD name, so it's not
			 * a regular network interface.
			 */
			continue;
		}
		if (CFStringCompare(name_CFString, bsdname_CFString, 0) == 0) {
			/*
			 * This is the interface.
			 * First, get the friendly name.
			 */
			friendly_name_CFString = SCNetworkInterfaceGetLocalizedDisplayName(interface);
			if (friendly_name_CFString != NULL)
				if_info->friendly_name = CFString_to_C_string(friendly_name_CFString);

			/*
			 * Now get the interface type.
			 */
			interface_type_CFString = SCNetworkInterfaceGetInterfaceType(interface);
			if (CFStringCompare(interface_type_CFString,
			    kSCNetworkInterfaceTypeIEEE80211, 0) == kCFCompareEqualTo)
				if_info->type = IF_WIRELESS;
			else if (CFStringCompare(interface_type_CFString,
			    kSCNetworkInterfaceTypeBluetooth, 0) == kCFCompareEqualTo)
				if_info->type = IF_BLUETOOTH;
			else if (CFStringCompare(interface_type_CFString,
			    kSCNetworkInterfaceTypeModem, 0) == kCFCompareEqualTo)
				if_info->type = IF_DIALUP;
			else if (CFStringCompare(interface_type_CFString,
			    kSCNetworkInterfaceTypePPP, 0) == kCFCompareEqualTo)
				if_info->type = IF_DIALUP;
			else if (CFStringCompare(interface_type_CFString,
			    kSCNetworkInterfaceTypeWWAN, 0) == kCFCompareEqualTo)
				if_info->type = IF_DIALUP;
			else
				if_info->type = IF_WIRED;
			break;
		}
	}

	CFRelease(interfaces);
	CFRelease(name_CFString);
}
#elif defined(__linux__)
/*
 * Linux doesn't offer any form of "friendly name", but you can
 * determine an interface type to some degree.
 */
static void
add_unix_interface_ifinfo(if_info_t *if_info, const char *name,
			  const char *description _U_)
{
	char *wireless_path;
	ws_statb64 statb;

	/*
	 * Look for /sys/class/net/{device}/wireless.  If it exists,
	 * it's a wireless interface.
	 */
	wireless_path = g_strdup_printf("/sys/class/net/%s/wireless", name);
	if (wireless_path != NULL) {
		if (ws_stat64(wireless_path, &statb) == 0)
			if_info->type = IF_WIRELESS;
		g_free(wireless_path);
	}
	if (if_info->type == IF_WIRED) {
		/*
		 * We still don't know what it is.  Check for
		 * Bluetooth and USB devices.
		 */
		if (strstr(name, "bluetooth") != NULL) {
			/*
			 * XXX - this is for raw Bluetooth capture; what
			 * about IP-over-Bluetooth devices?
			 */
			if_info->type = IF_BLUETOOTH;
		} else if (strstr(name, "usbmon") != NULL)
			if_info->type = IF_USB;
	}
}
#else
/*
 * On other UN*Xes, if there is a description, it's a friendly
 * name, and there is no vendor description.  ("Other UN*Xes"
 * currently means "FreeBSD and OpenBSD".)
 */
void
add_unix_interface_ifinfo(if_info_t *if_info, const char *name _U_,
			  const char *description)
{
	if_info->friendly_name = g_strdup(description);
}
#endif

if_info_t *
if_info_new(const char *name, const char *description, gboolean loopback)
{
	if_info_t *if_info;
#ifdef _WIN32
	const char *guid_text;
	GUID guid;
#endif

	if_info = (if_info_t *)g_malloc(sizeof (if_info_t));
	if_info->name = g_strdup(name);
	if_info->friendly_name = NULL;	/* default - unknown */
	if_info->vendor_description = NULL;
	if_info->type = IF_WIRED;	/* default */
#ifdef HAVE_EXTCAP
	if_info->extcap = g_strdup("");
#endif
#ifdef _WIN32
	/*
	 * Get the interface type.
	 *
	 * Much digging failed to reveal any obvious way to get something
	 * such as the SNMP MIB-II ifType value for an interface:
	 *
	 *    http://www.iana.org/assignments/ianaiftype-mib
	 *
	 * by making some NDIS request.  And even if there were such
	 * a way, there's no guarantee that the ifType reflects an
	 * interface type that a user would view as correct (for
	 * example, some systems report Wi-Fi interfaces as
	 * Ethernet interfaces).
	 *
	 * So we look for keywords in the vendor's interface
	 * description.
	 */
	if (description && (strstr(description, "generic dialup") != NULL ||
	    strstr(description, "PPP/SLIP") != NULL)) {
		if_info->type = IF_DIALUP;
	} else if (description && (strstr(description, "Wireless") != NULL ||
	    strstr(description,"802.11") != NULL)) {
		if_info->type = IF_WIRELESS;
	} else if (description && strstr(description, "AirPcap") != NULL ||
	    strstr(name, "airpcap") != NULL) {
		if_info->type = IF_AIRPCAP;
	} else if (description && strstr(description, "Bluetooth") != NULL ) {
		if_info->type = IF_BLUETOOTH;
	} else if (description && strstr(description, "VMware") != NULL) {
		/*
		 * Bridge, NAT, or host-only interface on a VMware host.
		 *
		 * XXX - what about guest interfaces?
		 */
		if_info->type = IF_VIRTUAL;
	}

	/*
	 * On Windows, the "description" is a vendor description,
	 * and the friendly name isn't returned by WinPcap.
	 * Fetch it ourselves.
	 */

	/*
	 * Skip over the "\Device\NPF_" prefix in the device name,
	 * if present.
	 */
	if (strncmp("\\Device\\NPF_", name, 12) == 0)
		guid_text = name + 12;
	else
		guid_text = name;

	/* Now try to parse what remains as a GUID. */
	if (parse_as_guid(guid_text, &guid)) {
		/*
		 * Success. Try to get a friendly name using the GUID.
		 * As this is a regular interface, the description is a
		 * vendor description.
		 */
		if_info->friendly_name = get_interface_friendly_name_from_device_guid(&guid);
		if_info->vendor_description = g_strdup(description);
	} else {
		/*
		 * This is probably not a regular interface; we only
		 * support NT 5 (W2K) and later, so all regular interfaces
		 * should have GUIDs at the end of the name.  Therefore,
		 * the description, if supplied, is a friendly name
		 * provided by WinPcap, and there is no vendor
		 * description.
		 */
		if_info->friendly_name = g_strdup(description);
		if_info->vendor_description = NULL;
	}
#else
	/*
	 * On UN*X, if there is a description, it's a friendly
	 * name, and there is no vendor description.
	 *
	 * Try the platform's way of getting a friendly name and
	 * interface type first.
	 *
	 * If that fails, then, for a loopback interface, give it the
	 * friendly name "Loopback" and, for VMware interfaces,
	 * give them the type IF_VIRTUAL.
	 */
	add_unix_interface_ifinfo(if_info, name, description);
	if (if_info->type == IF_WIRED) {
		/*
		 * This is the default interface type.
		 *
		 * Bridge, NAT, or host-only interfaces on VMWare hosts
		 * have the name vmnet[0-9]+. Guests might use a native
		 * (LANCE or E1000) driver or the vmxnet driver.  Check
		 * the name.
		 */
		if (g_ascii_strncasecmp(name, "vmnet", 5) == 0)
			if_info->type = IF_VIRTUAL;
		else if (g_ascii_strncasecmp(name, "vmxnet", 6) == 0)
			if_info->type = IF_VIRTUAL;
	}
	if (if_info->friendly_name == NULL) {
		/*
		 * We couldn't get interface information using platform-
		 * dependent calls.
		 *
		 * If this is a loopback interface, give it a
		 * "friendly name" of "Loopback".
		 */
		if (loopback)
			if_info->friendly_name = g_strdup("Loopback");
	}
	if_info->vendor_description = NULL;
#endif
	if_info->loopback = loopback;
	if_info->addrs = NULL;
	return if_info;
}

void
if_info_add_address(if_info_t *if_info, struct sockaddr *addr)
{
	if_addr_t *if_addr;
	struct sockaddr_in *ai;
	struct sockaddr_in6 *ai6;

	switch (addr->sa_family) {

	case AF_INET:
		ai = (struct sockaddr_in *)(void *)addr;
		if_addr = (if_addr_t *)g_malloc(sizeof(*if_addr));
		if_addr->ifat_type = IF_AT_IPv4;
		if_addr->addr.ip4_addr =
		    *((guint32 *)&(ai->sin_addr.s_addr));
		if_info->addrs = g_slist_append(if_info->addrs, if_addr);
		break;

	case AF_INET6:
		ai6 = (struct sockaddr_in6 *)(void *)addr;
		if_addr = (if_addr_t *)g_malloc(sizeof(*if_addr));
		if_addr->ifat_type = IF_AT_IPv6;
		memcpy((void *)&if_addr->addr.ip6_addr,
		    (void *)&ai6->sin6_addr.s6_addr,
		    sizeof if_addr->addr.ip6_addr);
		if_info->addrs = g_slist_append(if_info->addrs, if_addr);
		break;
	}
}

#ifdef HAVE_PCAP_FINDALLDEVS
/*
 * Get all IP address information for the given interface.
 */
static void
if_info_ip(if_info_t *if_info, pcap_if_t *d)
{
	pcap_addr_t *a;

	/* All addresses */
	for (a = d->addresses; a != NULL; a = a->next) {
		if (a->addr != NULL)
			if_info_add_address(if_info, a->addr);
	}
}

#ifdef HAVE_PCAP_REMOTE
GList *
get_interface_list_findalldevs_ex(const char *source,
				  struct pcap_rmtauth *auth,
				  int *err, char **err_str)
{
	GList  *il = NULL;
	pcap_if_t *alldevs, *dev;
	if_info_t *if_info;
	/*
	 * WinPcap can overflow PCAP_ERRBUF_SIZE if the host is unreachable.
	 * Fudge a larger size.
	 */
	char errbuf[PCAP_ERRBUF_SIZE*4];

	if (pcap_findalldevs_ex((char *)source, auth, &alldevs, errbuf) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		if (err_str != NULL)
			*err_str = cant_get_if_list_error_message(errbuf);
		return NULL;
	}

	if (alldevs == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = 0;
		if (err_str != NULL)
			*err_str = NULL;
		return NULL;
	}

	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if_info = if_info_new(dev->name, dev->description,
		    (dev->flags & PCAP_IF_LOOPBACK) ? TRUE : FALSE);
		il = g_list_append(il, if_info);
		if_info_ip(if_info, dev);
	}
	pcap_freealldevs(alldevs);

	return il;
}
#endif

GList *
get_interface_list_findalldevs(int *err, char **err_str)
{
	GList  *il = NULL;
	pcap_if_t *alldevs, *dev;
	if_info_t *if_info;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		if (err_str != NULL)
			*err_str = cant_get_if_list_error_message(errbuf);
		return NULL;
	}

	if (alldevs == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = 0;
		if (err_str != NULL)
			*err_str = NULL;
		return NULL;
	}

	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if_info = if_info_new(dev->name, dev->description,
		    (dev->flags & PCAP_IF_LOOPBACK) ? TRUE : FALSE);
		il = g_list_append(il, if_info);
		if_info_ip(if_info, dev);
	}
	pcap_freealldevs(alldevs);

	return il;
}
#endif /* HAVE_PCAP_FINDALLDEVS */

static void
free_if_info_addr_cb(gpointer addr, gpointer user_data _U_)
{
	g_free(addr);
}

static void
free_if_cb(gpointer data, gpointer user_data _U_)
{
	if_info_t *if_info = (if_info_t *)data;

	g_free(if_info->name);
	g_free(if_info->friendly_name);
	g_free(if_info->vendor_description);
#ifdef HAVE_EXTCAP
	g_free(if_info->extcap);
#endif

	g_slist_foreach(if_info->addrs, free_if_info_addr_cb, NULL);
	g_slist_free(if_info->addrs);
	g_free(if_info);
}

void
free_interface_list(GList *if_list)
{
	g_list_foreach(if_list, free_if_cb, NULL);
	g_list_free(if_list);
}

#if !defined(HAVE_PCAP_DATALINK_NAME_TO_VAL) || !defined(HAVE_PCAP_DATALINK_VAL_TO_NAME) || !defined(HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION)
struct dlt_choice {
	const char *name;
	const char *description;
	int	dlt;
};

#define DLT_CHOICE(code, description) { #code, description, code }
#define DLT_CHOICE_SENTINEL { NULL, NULL, 0 }

static struct dlt_choice dlt_choices[] = {
	DLT_CHOICE(DLT_NULL,		       "BSD loopback"),
	DLT_CHOICE(DLT_EN10MB,		       "Ethernet"),
	DLT_CHOICE(DLT_IEEE802,		       "Token ring"),
	DLT_CHOICE(DLT_ARCNET,		       "ARCNET"),
	DLT_CHOICE(DLT_SLIP,		       "SLIP"),
	DLT_CHOICE(DLT_PPP,		       "PPP"),
	DLT_CHOICE(DLT_FDDI,		       "FDDI"),
	DLT_CHOICE(DLT_ATM_RFC1483,	       "RFC 1483 IP-over-ATM"),
	DLT_CHOICE(DLT_RAW,		       "Raw IP"),
	DLT_CHOICE(DLT_SLIP_BSDOS,	       "BSD/OS SLIP"),
	DLT_CHOICE(DLT_PPP_BSDOS,	       "BSD/OS PPP"),
	DLT_CHOICE(DLT_ATM_CLIP,	       "Linux Classical IP-over-ATM"),
	DLT_CHOICE(DLT_PPP_SERIAL,	       "PPP over serial"),
	DLT_CHOICE(DLT_PPP_ETHER,	       "PPPoE"),
	DLT_CHOICE(DLT_C_HDLC,		       "Cisco HDLC"),
	DLT_CHOICE(DLT_IEEE802_11,	       "802.11"),
	DLT_CHOICE(DLT_FRELAY,		       "Frame Relay"),
	DLT_CHOICE(DLT_LOOP,		       "OpenBSD loopback"),
	DLT_CHOICE(DLT_ENC,		       "OpenBSD encapsulated IP"),
	DLT_CHOICE(DLT_LINUX_SLL,	       "Linux cooked"),
	DLT_CHOICE(DLT_LTALK,		       "Localtalk"),
	DLT_CHOICE(DLT_PFLOG,		       "OpenBSD pflog file"),
	DLT_CHOICE(DLT_PRISM_HEADER,	       "802.11 plus Prism header"),
	DLT_CHOICE(DLT_IP_OVER_FC,	       "RFC 2625 IP-over-Fibre Channel"),
	DLT_CHOICE(DLT_SUNATM,		       "Sun raw ATM"),
	DLT_CHOICE(DLT_IEEE802_11_RADIO,       "802.11 plus BSD radio information header"),
	DLT_CHOICE(DLT_APPLE_IP_OVER_IEEE1394, "Apple IP-over-IEEE 1394"),
	DLT_CHOICE(DLT_ARCNET_LINUX,	       "Linux ARCNET"),
	DLT_CHOICE(DLT_LINUX_IRDA,	       "Linux IrDA"),
	DLT_CHOICE(DLT_IEEE802_11_RADIO_AVS,   "802.11 plus AVS radio information header"),
	DLT_CHOICE_SENTINEL
};

#if !defined(HAVE_PCAP_DATALINK_NAME_TO_VAL)
static int
pcap_datalink_name_to_val(const char *name)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (g_ascii_strcasecmp(dlt_choices[i].name + sizeof("DLT_") - 1,
		    name) == 0)
			return (dlt_choices[i].dlt);
	}
	return (-1);
}
#endif /* defined(HAVE_PCAP_DATALINK_NAME_TO_VAL) */

#if !defined(HAVE_PCAP_DATALINK_VAL_TO_NAME)
static const char *
pcap_datalink_val_to_name(int dlt)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (dlt_choices[i].dlt == dlt)
			return (dlt_choices[i].name + sizeof("DLT_") - 1);
	}
	return (NULL);
}
#endif /* defined(HAVE_PCAP_DATALINK_VAL_TO_NAME) */

#if !defined(HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION)
const char *
pcap_datalink_val_to_description(int dlt)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (dlt_choices[i].dlt == dlt)
			return (dlt_choices[i].description);
	}
	return (NULL);
}
#endif /* defined(HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION) */

#endif /* !defined(HAVE_PCAP_DATALINK_VAL_TO_NAME) || !defined(HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION) */

static void
free_linktype_cb(gpointer data, gpointer user_data _U_)
{
	data_link_info_t *linktype_info = (data_link_info_t *)data;

	g_free(linktype_info->name);
	g_free(linktype_info->description);
	g_free(linktype_info);
}

void
free_if_capabilities(if_capabilities_t *caps)
{
	g_list_foreach(caps->data_link_types, free_linktype_cb, NULL);
	g_list_free(caps->data_link_types);
	g_free(caps);
}

const char *
linktype_val_to_name(int dlt)
{
	return pcap_datalink_val_to_name(dlt);
}

int
linktype_name_to_val(const char *linktype)
{
	return pcap_datalink_name_to_val(linktype);
}

/*
 * Get the data-link type for a libpcap device.
 * This works around AIX 5.x's non-standard and incompatible-with-the-
 * rest-of-the-universe libpcap.
 */
int
get_pcap_datalink(pcap_t *pch, const char *devicename
#ifndef _AIX
    _U_)
#else
    )
#endif
{
	int datalink;
#ifdef _AIX
	const char *ifacename;
#endif

	datalink = pcap_datalink(pch);
#ifdef _AIX

	/*
	 * The libpcap that comes with AIX 5.x uses RFC 1573 ifType values
	 * rather than DLT_ values for link-layer types; the ifType values
	 * for LAN devices are:
	 *
	 *  Ethernet        6
	 *  802.3           7
	 *  Token Ring      9
	 *  FDDI            15
	 *
	 * and the ifType value for a loopback device is 24.
	 *
	 * The AIX names for LAN devices begin with:
	 *
	 *  Ethernet                en
	 *  802.3                   et
	 *  Token Ring              tr
	 *  FDDI                    fi
	 *
	 * and the AIX names for loopback devices begin with "lo".
	 *
	 * (The difference between "Ethernet" and "802.3" is presumably
	 * whether packets have an Ethernet header, with a packet type,
	 * or an 802.3 header, with a packet length, followed by an 802.2
	 * header and possibly a SNAP header.)
	 *
	 * If the device name matches "datalink" interpreted as an ifType
	 * value, rather than as a DLT_ value, we will assume this is AIX's
	 * non-standard, incompatible libpcap, rather than a standard libpcap,
	 * and will map the link-layer type to the standard DLT_ value for
	 * that link-layer type, as that's what the rest of Wireshark expects.
	 *
	 * (This means the capture files won't be readable by a tcpdump
	 * linked with AIX's non-standard libpcap, but so it goes.  They
	 * *will* be readable by standard versions of tcpdump, Wireshark,
	 * and so on.)
	 *
	 * XXX - if we conclude we're using AIX libpcap, should we also
	 * set a flag to cause us to assume the time stamps are in
	 * seconds-and-nanoseconds form, and to convert them to
	 * seconds-and-microseconds form before processing them and
	 * writing them out?
	 */

	/*
	 * Find the last component of the device name, which is the
	 * interface name.
	 */
	ifacename = strchr(devicename, '/');
	if (ifacename == NULL)
		ifacename = devicename;

	/* See if it matches any of the LAN device names. */
	if (strncmp(ifacename, "en", 2) == 0) {
		if (datalink == 6) {
			/*
			 * That's the RFC 1573 value for Ethernet;
			 * map it to DLT_EN10MB.
			 */
			datalink = 1;
		}
	} else if (strncmp(ifacename, "et", 2) == 0) {
		if (datalink == 7) {
			/*
			 * That's the RFC 1573 value for 802.3;
			 * map it to DLT_EN10MB.
			 *
			 * (libpcap, tcpdump, Wireshark, etc. don't
			 * care if it's Ethernet or 802.3.)
			 */
			datalink = 1;
		}
	} else if (strncmp(ifacename, "tr", 2) == 0) {
		if (datalink == 9) {
			/*
			 * That's the RFC 1573 value for 802.5 (Token Ring);
			 * map it to DLT_IEEE802, which is what's used for
			 * Token Ring.
			 */
			datalink = 6;
		}
	} else if (strncmp(ifacename, "fi", 2) == 0) {
		if (datalink == 15) {
			/*
			 * That's the RFC 1573 value for FDDI;
			 * map it to DLT_FDDI.
			 */
			datalink = 10;
		}
	} else if (strncmp(ifacename, "lo", 2) == 0) {
		if (datalink == 24) {
			/*
			 * That's the RFC 1573 value for "software loopback"
			 * devices; map it to DLT_NULL, which is what's used
			 * for loopback devices on BSD.
			 */
			datalink = 0;
		}
	}
#endif

	return datalink;
}

/* Set the data link type on a pcap. */
gboolean
set_pcap_datalink(pcap_t *pcap_h, int datalink, char *name,
    char *errmsg, size_t errmsg_len,
    char *secondary_errmsg, size_t secondary_errmsg_len)
{
	char *set_datalink_err_str;

	if (datalink == -1)
		return TRUE; /* just use the default */
#ifdef HAVE_PCAP_SET_DATALINK
	if (pcap_set_datalink(pcap_h, datalink) == 0)
		return TRUE; /* no error */
	set_datalink_err_str = pcap_geterr(pcap_h);
#else
	/* Let them set it to the type it is; reject any other request. */
	if (get_pcap_datalink(pcap_h, name) == datalink)
		return TRUE; /* no error */
	set_datalink_err_str =
		"That DLT isn't one of the DLTs supported by this device";
#endif
	g_snprintf(errmsg, (gulong) errmsg_len, "Unable to set data link type on interface '%s' (%s).",
	    name, set_datalink_err_str);
	/*
	 * If the error isn't "XXX is not one of the DLTs supported by this device",
	 * tell the user to tell the Wireshark developers about it.
	 */
	if (strstr(set_datalink_err_str, "is not one of the DLTs supported by this device") == NULL)
		g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len, please_report);
	else
		secondary_errmsg[0] = '\0';
	return FALSE;
}

static data_link_info_t *
create_data_link_info(int dlt)
{
	data_link_info_t *data_link_info;
	const char *text;

	data_link_info = (data_link_info_t *)g_malloc(sizeof (data_link_info_t));
	data_link_info->dlt = dlt;
	text = pcap_datalink_val_to_name(dlt);
	if (text != NULL)
		data_link_info->name = g_strdup(text);
	else
		data_link_info->name = g_strdup_printf("DLT %d", dlt);
	text = pcap_datalink_val_to_description(dlt);
	if (text != NULL)
		data_link_info->description = g_strdup(text);
	else
		data_link_info->description = NULL;
	return data_link_info;
}

static GList *
get_data_link_types(pcap_t *pch, interface_options *interface_opts,
    char **err_str)
{
	GList *data_link_types;
	int deflt;
#ifdef HAVE_PCAP_LIST_DATALINKS
	int *linktypes;
	int i, nlt;
#endif
	data_link_info_t *data_link_info;

	deflt = get_pcap_datalink(pch, interface_opts->name);
#ifdef HAVE_PCAP_LIST_DATALINKS
	nlt = pcap_list_datalinks(pch, &linktypes);
	if (nlt < 0) {
		/*
		 * This either returns a negative number for an error
		 *  or returns a number > 0 and sets linktypes.
		 */
		pcap_close(pch);
		if (err_str != NULL) {
			if (nlt == PCAP_ERROR)
				*err_str = g_strdup_printf("pcap_list_datalinks() failed: %s",
				    pcap_geterr(pch));
			else
				*err_str = g_strdup(pcap_statustostr(nlt));
		}
		return NULL;
	}
	data_link_types = NULL;
	for (i = 0; i < nlt; i++) {
		data_link_info = create_data_link_info(linktypes[i]);

		/*
		 * XXX - for 802.11, make the most detailed 802.11
		 * version the default, rather than the one the
		 * device has as the default?
		 */
		if (linktypes[i] == deflt)
			data_link_types = g_list_prepend(data_link_types,
			    data_link_info);
		else
			data_link_types = g_list_append(data_link_types,
			    data_link_info);
	}
#ifdef HAVE_PCAP_FREE_DATALINKS
	pcap_free_datalinks(linktypes);
#else
	/*
	 * In Windows, there's no guarantee that if you have a library
	 * built with one version of the MSVC++ run-time library, and
	 * it returns a pointer to allocated data, you can free that
	 * data from a program linked with another version of the
	 * MSVC++ run-time library.
	 *
	 * This is not an issue on UN*X.
	 *
	 * See the mail threads starting at
	 *
	 *	https://www.winpcap.org/pipermail/winpcap-users/2006-September/001421.html
	 *
	 * and
	 *
	 *	https://www.winpcap.org/pipermail/winpcap-users/2008-May/002498.html
	 */
#ifndef _WIN32
#define xx_free free  /* hack so checkAPIs doesn't complain */
	xx_free(linktypes);
#endif /* _WIN32 */
#endif /* HAVE_PCAP_FREE_DATALINKS */
#else /* HAVE_PCAP_LIST_DATALINKS */

	data_link_info = create_data_link_info(deflt);
	data_link_types = g_list_append(data_link_types, data_link_info);
#endif /* HAVE_PCAP_LIST_DATALINKS */

	if (err_str != NULL)
		*err_str = NULL;
	return data_link_types;
}

#ifdef HAVE_PCAP_CREATE
#ifdef HAVE_BONDING
static gboolean
is_linux_bonding_device(const char *ifname)
{
	int fd;
	struct ifreq ifr;
	ifbond ifb;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return FALSE;

	memset(&ifr, 0, sizeof ifr);
	g_strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
	memset(&ifb, 0, sizeof ifb);
	ifr.ifr_data = (caddr_t)&ifb;
#if defined(SIOCBONDINFOQUERY)
	if (ioctl(fd, SIOCBONDINFOQUERY, &ifr) == 0) {
		close(fd);
		return TRUE;
	}
#else
	if (ioctl(fd, BOND_INFO_QUERY_OLD, &ifr) == 0) {
		close(fd);
		return TRUE;
	}
#endif

	close(fd);
	return FALSE;
}
#else
static gboolean
is_linux_bonding_device(const char *ifname _U_)
{
	return FALSE;
}
#endif

if_capabilities_t *
get_if_capabilities_pcap_create(interface_options *interface_opts,
    char **err_str)
{
	if_capabilities_t *caps;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pch;
	int status;

	/*
	 * Allocate the interface capabilities structure.
	 */
	caps = (if_capabilities_t *)g_malloc(sizeof *caps);

	pch = pcap_create(interface_opts->name, errbuf);
	if (pch == NULL) {
		if (err_str != NULL)
			*err_str = g_strdup(errbuf);
		g_free(caps);
		return NULL;
	}
	if (is_linux_bonding_device(interface_opts->name)) {
		/*
		 * Linux bonding device; not Wi-Fi, so no monitor mode, and
		 * calling pcap_can_set_rfmon() might get a "no such device"
		 * error.
		 */
		status = 0;
	} else {
		/*
		 * Not a Linux bonding device, so go ahead.
		 */
		status = pcap_can_set_rfmon(pch);
	}
	if (status < 0) {
		/* Error. */
		if (status == PCAP_ERROR)
			*err_str = g_strdup_printf("pcap_can_set_rfmon() failed: %s",
			    pcap_geterr(pch));
		else
			*err_str = g_strdup(pcap_statustostr(status));
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}
	if (status == 0)
		caps->can_set_rfmon = FALSE;
	else if (status == 1) {
		caps->can_set_rfmon = TRUE;
		if (interface_opts->monitor_mode)
			pcap_set_rfmon(pch, 1);
	} else {
		if (err_str != NULL) {
			*err_str = g_strdup_printf("pcap_can_set_rfmon() returned %d",
			    status);
		}
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	status = pcap_activate(pch);
	if (status < 0) {
		/* Error.  We ignore warnings (status > 0). */
		if (err_str != NULL) {
			if (status == PCAP_ERROR)
				*err_str = g_strdup_printf("pcap_activate() failed: %s",
				    pcap_geterr(pch));
			else
				*err_str = g_strdup(pcap_statustostr(status));
		}
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	caps->data_link_types = get_data_link_types(pch, interface_opts,
	    err_str);
	if (caps->data_link_types == NULL) {
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	pcap_close(pch);

	if (err_str != NULL)
		*err_str = NULL;
	return caps;
}

pcap_t *
open_capture_device_pcap_create(capture_options *capture_opts
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
    ,
#else
    _U_,
#endif
    interface_options *interface_opts, int timeout,
    char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
	int err;

	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "Calling pcap_create() using %s.", interface_opts->name);
	pcap_h = pcap_create(interface_opts->name, *open_err_str);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_create() returned %p.", (void *)pcap_h);
	if (pcap_h != NULL) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "Calling pcap_set_snaplen() with snaplen %d.",
		    interface_opts->snaplen);
		pcap_set_snaplen(pcap_h, interface_opts->snaplen);
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "Calling pcap_set_promisc() with promisc_mode %d.",
		    interface_opts->promisc_mode);
		pcap_set_promisc(pcap_h, interface_opts->promisc_mode);
		pcap_set_timeout(pcap_h, timeout);

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
		/*
		 * If we're writing pcap-ng files, try to enable
		 * nanosecond-resolution capture; any code that
		 * can read pcap-ng files must be able to handle
		 * nanosecond-resolution time stamps.  We don't
		 * care whether it succeeds or fails - if it fails,
		 * we just use the microsecond-precision time stamps
		 * we get.
		 *
		 * If we're writing pcap files, don't try to enable
		 * nanosecond-resolution capture, as not all code
		 * that reads pcap files recognizes the nanosecond-
		 * resolution pcap file magic number.
		 * We don't care whether this succeeds or fails; if it
		 * fails (because we don't have pcap_set_tstamp_precision(),
		 * or because we do but the OS or device doesn't support
		 * nanosecond resolution timing), we just use microsecond-
		 * resolution time stamps.
		 */
		if (capture_opts->use_pcapng)
			request_high_resolution_timestamp(pcap_h);
#endif /* HAVE_PCAP_SET_TSTAMP_PRECISION */

		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "buffersize %d.", interface_opts->buffer_size);
		if (interface_opts->buffer_size != 0)
			pcap_set_buffer_size(pcap_h,
			    interface_opts->buffer_size * 1024 * 1024);
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "monitor_mode %d.", interface_opts->monitor_mode);
		if (interface_opts->monitor_mode)
			pcap_set_rfmon(pcap_h, 1);
		err = pcap_activate(pcap_h);
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "pcap_activate() returned %d.", err);
		if (err < 0) {
			/* Failed to activate, set to NULL */
			if (err == PCAP_ERROR)
				g_strlcpy(*open_err_str, pcap_geterr(pcap_h),
				    sizeof *open_err_str);
			else
				g_strlcpy(*open_err_str, pcap_statustostr(err),
				    sizeof *open_err_str);
			pcap_close(pcap_h);
			pcap_h = NULL;
		}
	}
	return pcap_h;
}
#endif /* HAVE_PCAP_CREATE */

if_capabilities_t *
get_if_capabilities_pcap_open_live(interface_options *interface_opts,
    char **err_str)
{
	if_capabilities_t *caps;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pch;

	/*
	 * Allocate the interface capabilities structure.
	 */
	caps = (if_capabilities_t *)g_malloc(sizeof *caps);

	pch = pcap_open_live(interface_opts->name, MIN_PACKET_SIZE, 0, 0,
	    errbuf);
	caps->can_set_rfmon = FALSE;
	if (pch == NULL) {
		if (err_str != NULL)
			*err_str = g_strdup(errbuf[0] == '\0' ? "Unknown error (pcap bug; actual error cause not reported)" : errbuf);
		g_free(caps);
		return NULL;
	}
	caps->data_link_types = get_data_link_types(pch, interface_opts,
	    err_str);
	if (caps->data_link_types == NULL) {
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	pcap_close(pch);

	if (err_str != NULL)
		*err_str = NULL;
	return caps;
}

pcap_t *
open_capture_device_pcap_open_live(interface_options *interface_opts,
    int timeout, char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;

	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_open_live() calling using name %s, snaplen %d, promisc_mode %d.",
	    interface_opts->name, interface_opts->snaplen,
	    interface_opts->promisc_mode);
	pcap_h = pcap_open_live(interface_opts->name, interface_opts->snaplen,
	    interface_opts->promisc_mode, timeout, *open_err_str);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_open_live() returned %p.", (void *)pcap_h);

#ifdef _WIN32
	/* If the open succeeded, try to set the capture buffer size. */
	if (pcap_h && interface_opts->buffer_size > 1) {
		/*
		 * We have no mechanism to report a warning if this
		 * fails; we just keep capturing with the smaller buffer,
		 * as is the case on systems with BPF and pcap_create()
		 * and pcap_set_buffer_size(), where pcap_activate() just
		 * silently clamps the buffer size to the maximum.
		 */
		pcap_setbuff(pcap_h, interface_opts->buffer_size * 1024 * 1024);
	}
#endif

	return pcap_h;
}

/*
 * Get the capabilities of a network device.
 */
if_capabilities_t *
get_if_capabilities(interface_options *interface_opts, char **err_str)
{
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
    if_capabilities_t *caps;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pch;
    int deflt;
    data_link_info_t *data_link_info;

    if (strncmp (interface_opts->name, "rpcap://", 8) == 0) {
        struct pcap_rmtauth auth;

        /*
         * Allocate the interface capabilities structure.
         */
        caps = (if_capabilities_t *)g_malloc(sizeof *caps);

        auth.type = interface_opts->auth_type == CAPTURE_AUTH_PWD ?
            RPCAP_RMTAUTH_PWD : RPCAP_RMTAUTH_NULL;
        auth.username = interface_opts->auth_username;
        auth.password = interface_opts->auth_password;

        /*
         * WinPcap 4.1.2, and possibly earlier versions, have a bug
         * wherein, when an open with an rpcap: URL fails, the error
         * message for the error is not copied to errbuf and whatever
         * on-the-stack junk is in errbuf is treated as the error
         * message.
         *
         * To work around that (and any other bugs of that sort), we
         * initialize errbuf to an empty string.  If we get an error
         * and the string is empty, we report it as an unknown error.
         * (If we *don't* get an error, and the string is *non*-empty,
         * that could be a warning returned, such as "can't turn
         * promiscuous mode on"; we currently don't do so.)
         */
        errbuf[0] = '\0';
        pch = pcap_open(interface_opts->name, MIN_PACKET_SIZE, 0, 0, &auth,
            errbuf);
	if (pch == NULL) {
		if (err_str != NULL)
			*err_str = g_strdup(errbuf[0] == '\0' ? "Unknown error (pcap bug; actual error cause not reported)" : errbuf);
		g_free(caps);
		return NULL;
	}
        deflt = get_pcap_datalink(pch, interface_opts->name);
        data_link_info = create_data_link_info(deflt);
        caps->data_link_types = g_list_append(caps->data_link_types,
                                              data_link_info);
        pcap_close(pch);

        if (err_str != NULL)
            *err_str = NULL;
        return caps;
    }
#endif /* defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE) */

    /*
     * Local interface.
     */
    return get_if_capabilities_local(interface_opts, err_str);
}

pcap_t *
open_capture_device(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
	struct pcap_rmtauth auth;
#endif

	/* Open the network interface to capture from it.
	   Some versions of libpcap may put warnings into the error buffer
	   if they succeed; to tell if that's happened, we have to clear
	   the error buffer, and check if it's still a null string.  */
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Entering open_capture_device().");
	(*open_err_str)[0] = '\0';
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
	/*
	 * If we're opening a remote device, use pcap_open(); that's currently
	 * the only open routine that supports remote devices.
	 */
	if (strncmp (interface_opts->name, "rpcap://", 8) == 0) {
		auth.type = interface_opts->auth_type == CAPTURE_AUTH_PWD ?
		    RPCAP_RMTAUTH_PWD : RPCAP_RMTAUTH_NULL;
		auth.username = interface_opts->auth_username;
		auth.password = interface_opts->auth_password;

		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "Calling pcap_open() using name %s, snaplen %d, promisc_mode %d, datatx_udp %d, nocap_rpcap %d.",
		    interface_opts->name, interface_opts->snaplen,
		    interface_opts->promisc_mode, interface_opts->datatx_udp,
		    interface_opts->nocap_rpcap);
		pcap_h = pcap_open(interface_opts->name, interface_opts->snaplen,
		    /* flags */
		    (interface_opts->promisc_mode ? PCAP_OPENFLAG_PROMISCUOUS : 0) |
		    (interface_opts->datatx_udp ? PCAP_OPENFLAG_DATATX_UDP : 0) |
		    (interface_opts->nocap_rpcap ? PCAP_OPENFLAG_NOCAPTURE_RPCAP : 0),
		    timeout, &auth, *open_err_str);
		if (pcap_h == NULL) {
			/* Error - did pcap actually supply an error message? */
			if ((*open_err_str)[0] == '\0') {
				/*
				 * Work around known WinPcap bug wherein
				 * no error message is filled in on a
				 * failure to open an rpcap: URL.
				 */
				g_strlcpy(*open_err_str,
				    "Unknown error (pcap bug; actual error cause not reported)",
				    sizeof *open_err_str);
			}
		}
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "pcap_open() returned %p.", (void *)pcap_h);
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "open_capture_device %s : %s", pcap_h ? "SUCCESS" : "FAILURE", interface_opts->name);
		return pcap_h;
	}
#endif

	pcap_h = open_capture_device_local(capture_opts, interface_opts,
	    timeout, open_err_str);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "open_capture_device %s : %s", pcap_h ? "SUCCESS" : "FAILURE", interface_opts->name);
	return pcap_h;
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
