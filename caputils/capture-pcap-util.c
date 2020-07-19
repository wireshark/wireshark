/* capture-pcap-util.c
 * Utility routines for packet capture
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef __APPLE__
#include <dlfcn.h>
#endif

#include "ws_attributes.h"

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
#include <wsutil/please_report_bug.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif

#ifdef _WIN32
#include "caputils/capture_win_ifnames.h" /* windows friendly interface names */
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__)
/*
 * Needed for the code to get a device description.
 */
#include <errno.h>
#include <net/if.h>
#include <sys/sockio.h>
#endif

/*
 * Given an interface name, find the "friendly name" and interface
 * type for the interface.
 */

#if defined(HAVE_MACOS_FRAMEWORKS)

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <wsutil/cfutils.h>

/*
 * On macOS, we get the "friendly name" and interface type for the interface
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
 * not IFT_IEEE80211 (which isn't defined in macOS in any case).
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
static void
add_unix_interface_ifinfo(if_info_t *if_info, const char *name _U_,
			  const char *description)
{
	if_info->friendly_name = g_strdup(description);
}
#endif

if_info_t *
if_info_get(const char *name)
{
	char *description = NULL;
	if_info_t *if_info;
#ifdef SIOCGIFDESCR
	/*
	 * Try to fetch the description of this interface.
	 * XXX - this is only here because libpcap has no API to
	 * get the description of a *single* interface; it really
	 * needs both an API to get pcapng-IDB-style attributes
	 * for a single interface and to get a list of interfaces
	 * with pcapng-IDB-style attributes for each interface.
	 */
	int s;
	struct ifreq ifrdesc;
#ifndef IFDESCRSIZE
	size_t descrlen = 64;
#else
	size_t descrlen = IFDESCRSIZE;
#endif /* IFDESCRSIZE */

	/*
	 * Get the description for the interface.
	 */
	memset(&ifrdesc, 0, sizeof ifrdesc);
	g_strlcpy(ifrdesc.ifr_name, name, sizeof ifrdesc.ifr_name);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
#ifdef __FreeBSD__
		/*
		 * On FreeBSD, if the buffer isn't big enough for the
		 * description, the ioctl succeeds, but the description
		 * isn't copied, ifr_buffer.length is set to the description
		 * length, and ifr_buffer.buffer is set to NULL.
		 */
		for (;;) {
			g_free(description);
			if ((description = (char*)g_malloc(descrlen)) != NULL) {
				ifrdesc.ifr_buffer.buffer = description;
				ifrdesc.ifr_buffer.length = descrlen;
				if (ioctl(s, SIOCGIFDESCR, &ifrdesc) == 0) {
					if (ifrdesc.ifr_buffer.buffer ==
					    description)
						break;
					else
						descrlen = ifrdesc.ifr_buffer.length;
				} else {
					/*
					 * Failed to get interface description.
					 */
					g_free(description);
					description = NULL;
					break;
				}
			} else
				break;
		}
#else /* __FreeBSD__ */
		/*
		 * The only other OS that currently supports
		 * SIOCGIFDESCR is OpenBSD, and it has no way
		 * to get the description length - it's clamped
		 * to a maximum of IFDESCRSIZE.
		 */
		if ((description = (char*)g_malloc(descrlen)) != NULL) {
			ifrdesc.ifr_data = (caddr_t)description;
			if (ioctl(s, SIOCGIFDESCR, &ifrdesc) != 0) {
				/*
				 * Failed to get interface description.
				 */
				g_free(description);
				description = NULL;
			}
		}
#endif /* __FreeBSD__ */
		close(s);
		if (description != NULL && strlen(description) == 0) {
			/*
			 * Description is empty, so discard it.
			 */
			g_free(description);
			description = NULL;
		}
	}

#ifdef __FreeBSD__
	/*
	 * For FreeBSD, if we didn't get a description, and this is
	 * a device with a name of the form usbusN, label it as a USB
	 * bus.
	 */
	if (description == NULL) {
		if (strncmp(name, "usbus", 5) == 0) {
			/*
			 * OK, it begins with "usbus".
			 */
			long busnum;
			char *p;

			errno = 0;
			busnum = strtol(name + 5, &p, 10);
			if (errno == 0 && p != name + 5 && *p == '\0' &&
			    busnum >= 0 && busnum <= INT_MAX) {
				/*
				 * OK, it's a valid number that's not
				 * bigger than INT_MAX.  Construct
				 * a description from it.
				 */
				static const char descr_prefix[] = "USB bus number ";
				size_t descr_size;

				/*
				 * Allow enough room for a 32-bit bus number.
				 * sizeof (descr_prefix) includes the
				 * terminating NUL.
				 */
				descr_size = sizeof (descr_prefix) + 10;
				description = g_malloc(descr_size);
				if (description != NULL) {
					g_snprintf(description, descr_size,
					    "%s%ld", descr_prefix, busnum);
				}
			}
		}
	}
#endif /* __FreeBSD__ */
#endif /* SIOCGIFDESCR */
	if_info = if_info_new(name, description, FALSE);
	g_free(description);
	return if_info;
}

void
if_info_free(if_info_t *if_info)
{
	g_free(if_info->name);
	g_free(if_info->friendly_name);
	g_free(if_info->vendor_description);
	g_free(if_info->extcap);
	g_slist_free_full(if_info->addrs, g_free);
	g_free(if_info);
}

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
	if_info->extcap = g_strdup("");
#ifdef _WIN32
	/*
	 * Get the interface type.
	 *
	 * Much digging failed to reveal any obvious way to get something
	 * such as the SNMP MIB-II ifType value for an interface:
	 *
	 *    https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
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
	 * and the friendly name isn't returned by Npcap/WinPcap.
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
		if_info->addrs = g_slist_prepend(if_info->addrs, if_addr);
		break;

	case AF_INET6:
		ai6 = (struct sockaddr_in6 *)(void *)addr;
		if_addr = (if_addr_t *)g_malloc(sizeof(*if_addr));
		if_addr->ifat_type = IF_AT_IPv6;
		memcpy((void *)&if_addr->addr.ip6_addr,
		    (void *)&ai6->sin6_addr.s6_addr,
		    sizeof if_addr->addr.ip6_addr);
		if_info->addrs = g_slist_prepend(if_info->addrs, if_addr);
		break;
	}
}

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

	if(if_info->addrs){
		if_info->addrs = g_slist_reverse(if_info->addrs);
	}
}

#ifdef HAVE_PCAP_REMOTE
GList *
get_interface_list_findalldevs_ex(const char *hostname, const char *port,
			  int auth_type, const char *username,
			  const char *passwd, int *err, char **err_str)
{
	char source[PCAP_BUF_SIZE];
	struct pcap_rmtauth auth;
	GList  *il = NULL;
	pcap_if_t *alldevs, *dev;
	if_info_t *if_info;
	/*
	 * WinPcap can overflow PCAP_ERRBUF_SIZE if the host is unreachable.
	 * Fudge a larger size.
	 */
	char errbuf[PCAP_ERRBUF_SIZE*4];

	if (pcap_createsrcstr(source, PCAP_SRC_IFREMOTE, hostname, port,
			      NULL, errbuf) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		if (err_str != NULL)
			*err_str = cant_get_if_list_error_message(errbuf);
		return NULL;
	}

	auth.type = auth_type;
	auth.username = g_strdup(username);
	auth.password = g_strdup(passwd);

	if (pcap_findalldevs_ex(source, &auth, &alldevs, errbuf) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		if (err_str != NULL)
			*err_str = cant_get_if_list_error_message(errbuf);
		g_free(auth.username);
		g_free(auth.password);
		return NULL;
	}

	if (alldevs == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = 0;
		if (err_str != NULL)
			*err_str = NULL;
		g_free(auth.username);
		g_free(auth.password);
		return NULL;
	}

	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if_info = if_info_new(dev->name, dev->description,
		    (dev->flags & PCAP_IF_LOOPBACK) ? TRUE : FALSE);
		il = g_list_append(il, if_info);
		if_info_ip(if_info, dev);
	}
	pcap_freealldevs(alldevs);
	g_free(auth.username);
	g_free(auth.password);

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

static void
free_if_cb(gpointer data, gpointer user_data _U_)
{
	if_info_free((if_info_t *)data);
}

void
free_interface_list(GList *if_list)
{
	g_list_foreach(if_list, free_if_cb, NULL);
	g_list_free(if_list);
}

static void
free_linktype_cb(gpointer data, gpointer user_data _U_)
{
	data_link_info_t *linktype_info = (data_link_info_t *)data;

	g_free(linktype_info->name);
	g_free(linktype_info->description);
	g_free(linktype_info);
}

static void
free_timestamp_cb(gpointer data, gpointer user_data _U_)
{
	timestamp_info_t *timestamp_info = (timestamp_info_t *)data;

	g_free(timestamp_info->name);
	g_free(timestamp_info->description);
	g_free(data);
}

void
free_if_capabilities(if_capabilities_t *caps)
{
	g_list_foreach(caps->data_link_types, free_linktype_cb, NULL);
	g_list_free(caps->data_link_types);

	g_list_foreach(caps->timestamp_types, free_timestamp_cb, NULL);
	g_list_free(caps->timestamp_types);

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
get_pcap_datalink(pcap_t *pch,
#ifdef _AIX
    const char* devicename
#else
    const char* devicename _U_
#endif
    )
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
	if (pcap_set_datalink(pcap_h, datalink) == 0)
		return TRUE; /* no error */
	set_datalink_err_str = pcap_geterr(pcap_h);
	g_snprintf(errmsg, (gulong) errmsg_len, "Unable to set data link type on interface '%s' (%s).",
	    name, set_datalink_err_str);
	/*
	 * If the error isn't "XXX is not one of the DLTs supported by this device",
	 * tell the user to tell the Wireshark developers about it.
	 */
	if (strstr(set_datalink_err_str, "is not one of the DLTs supported by this device") == NULL)
		g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len,
		           "%s", please_report_bug());
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
	data_link_info->description = g_strdup(text);
	return data_link_info;
}

static GList *
get_data_link_types(pcap_t *pch, interface_options *interface_opts,
    cap_device_open_err *err, char **err_str)
{
	GList *data_link_types;
	int deflt;
	int *linktypes;
	int i, nlt;
	data_link_info_t *data_link_info;

	deflt = get_pcap_datalink(pch, interface_opts->name);
	nlt = pcap_list_datalinks(pch, &linktypes);
	if (nlt < 0) {
		/*
		 * A negative return is an error.
		 */
#ifdef HAVE_PCAP_CREATE
		/*
		 * If we have pcap_create(), we have
		 * pcap_statustostr(), and we can get back errors
		 * other than PCAP_ERROR (-1), such as
		 * PCAP_ERROR_NOT_ACTIVATED. and we should report
		 * them properly.
		 */
		if (nlt == PCAP_ERROR) {
			*err = CAP_DEVICE_OPEN_ERR_GENERIC;
			*err_str = g_strdup_printf("pcap_list_datalinks() failed: %s",
			    pcap_geterr(pch));
		} else {
			if (nlt == PCAP_ERROR_PERM_DENIED)
				*err = CAP_DEVICE_OPEN_ERR_PERMISSIONS;
			else
				*err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
			*err_str = g_strdup(pcap_statustostr(nlt));
		}
#else /* HAVE_PCAP_CREATE */
		*err = CAP_DEVICE_OPEN_ERR_GENERIC;
		*err_str = g_strdup_printf("pcap_list_datalinks() failed: %s",
		    pcap_geterr(pch));
#endif /* HAVE_PCAP_CREATE */
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

	*err_str = NULL;
	return data_link_types;
}

/* Get supported timestamp types for a libpcap device.  */
static GList*
get_pcap_timestamp_types(pcap_t *pch _U_, char **err_str _U_)
{
	GList *list = NULL;
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	int *types;
	int ntypes = pcap_list_tstamp_types(pch, &types);

	if (err_str)
		*err_str = ntypes < 0 ? pcap_geterr(pch) : NULL;

	if (ntypes <= 0)
		return NULL;

	while (ntypes--) {
		timestamp_info_t *info = (timestamp_info_t *)g_malloc(sizeof *info);
		info->name        = g_strdup(pcap_tstamp_type_val_to_name(types[ntypes]));
		info->description = g_strdup(pcap_tstamp_type_val_to_description(types[ntypes]));
		list = g_list_prepend(list, info);
	}

	pcap_free_tstamp_types(types);
#endif
	return list;
}

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
/*
 * Request high-resolution time stamps.
 *
 * We don't check for errors - if this fails, we just live with boring old
 * microsecond-resolution time stamps. The only errors pcap_set_tstamp_precision()
 * is documenting as returning are PCAP_ERROR_TSTAMP_PRECISION_NOTSUP, which just
 * means we can't do nanosecond precision on this adapter, in which case we
 * just live with whatever resolution we get by default, and
 * PCAP_ERROR_ACTIVATED, which shouldn't happen as we shouldn't call this
 * after we've activated the pcap_t.
 */
void
request_high_resolution_timestamp(pcap_t *pcap_h)
{
#ifdef __APPLE__
	/*
	 * On macOS, if you build with a newer SDK, pcap_set_tstamp_precision()
	 * is available, so the code will be built with it.
	 *
	 * However, if you then try to run on an older release that
	 * doesn't have pcap_set_tstamp_precision(), the dynamic linker
	 * will fail, as it won't find pcap_set_tstamp_precision().
	 *
	 * libpcap doesn't use macOS "weak linking" for new routines,
	 * so we can't just check whether a pointer to
	 * pcap_set_tstamp_precision() is null and, if it is, not
	 * call it.  We have to, instead, use dlopen() to load
	 * libpcap, and dlsym() to find a pointer to pcap_set_tstamp_precision(),
	 * and if we find the pointer, call it.
	 */
	static gboolean initialized = FALSE;
	static int (*p_pcap_set_tstamp_precision)(pcap_t *, int);

	if (!initialized) {
		p_pcap_set_tstamp_precision =
		    (int (*)(pcap_t *, int))
		      dlsym(RTLD_NEXT, "pcap_set_tstamp_precision");
		initialized = TRUE;
	}
	if (p_pcap_set_tstamp_precision != NULL)
		(*p_pcap_set_tstamp_precision)(pcap_h, PCAP_TSTAMP_PRECISION_NANO);
#else /* __APPLE__ */
	/*
	 * On other UN*Xes we require that we be run on an OS version
	 * with a libpcap equal to or later than the version with which
	 * we were built.
	 */
	pcap_set_tstamp_precision(pcap_h, PCAP_TSTAMP_PRECISION_NANO);
#endif /* __APPLE__ */
}

/*
 * Return TRUE if the pcap_t in question is set up for high-precision
 * time stamps, FALSE otherwise.
 */
gboolean
have_high_resolution_timestamp(pcap_t *pcap_h)
{
#ifdef __APPLE__
	/*
	 * See above.
	 */
	static gboolean initialized = FALSE;
	static int (*p_pcap_get_tstamp_precision)(pcap_t *);

	if (!initialized) {
		p_pcap_get_tstamp_precision =
		    (int (*)(pcap_t *))
		      dlsym(RTLD_NEXT, "pcap_get_tstamp_precision");
		initialized = TRUE;
	}
	if (p_pcap_get_tstamp_precision != NULL)
		return (*p_pcap_get_tstamp_precision)(pcap_h) == PCAP_TSTAMP_PRECISION_NANO;
	else
		return FALSE;	/* Can't get implies couldn't set */
#else /* __APPLE__ */
	/*
	 * On other UN*Xes we require that we be run on an OS version
	 * with a libpcap equal to or later than the version with which
	 * we were built.
	 */
	return pcap_get_tstamp_precision(pcap_h) == PCAP_TSTAMP_PRECISION_NANO;
#endif /* __APPLE__ */
}

#endif /* HAVE_PCAP_SET_TSTAMP_PRECISION */

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
    cap_device_open_err *err, char **err_str)
{
	if_capabilities_t *caps;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pch;
	int status;

	pch = pcap_create(interface_opts->name, errbuf);
	if (pch == NULL) {
		*err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
		*err_str = g_strdup(errbuf);
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
		if (status == PCAP_ERROR) {
			*err = CAP_DEVICE_OPEN_ERR_GENERIC;
			*err_str = g_strdup_printf("pcap_can_set_rfmon() failed: %s",
			    pcap_geterr(pch));
		} else {
			if (status == PCAP_ERROR_PERM_DENIED)
				*err = CAP_DEVICE_OPEN_ERR_PERMISSIONS;
			else
				*err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
			*err_str = g_strdup(pcap_statustostr(status));
		}
		pcap_close(pch);
		return NULL;
	}
	caps = (if_capabilities_t *)g_malloc(sizeof *caps);
	if (status == 0)
		caps->can_set_rfmon = FALSE;
	else if (status == 1) {
		caps->can_set_rfmon = TRUE;
		if (interface_opts->monitor_mode)
			pcap_set_rfmon(pch, 1);
	} else {
		*err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
		*err_str = g_strdup_printf("pcap_can_set_rfmon() returned %d",
		    status);
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	status = pcap_activate(pch);
	if (status < 0) {
		/* Error.  We ignore warnings (status > 0). */
		if (status == PCAP_ERROR) {
			*err = CAP_DEVICE_OPEN_ERR_GENERIC;
			*err_str = g_strdup_printf("pcap_activate() failed: %s",
			    pcap_geterr(pch));
		} else {
			if (status == PCAP_ERROR_PERM_DENIED)
				*err = CAP_DEVICE_OPEN_ERR_PERMISSIONS;
			else
				*err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
			*err_str = g_strdup(pcap_statustostr(status));
		}
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	caps->data_link_types = get_data_link_types(pch, interface_opts,
	    err, err_str);
	if (caps->data_link_types == NULL) {
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	caps->timestamp_types = get_pcap_timestamp_types(pch, NULL);

	pcap_close(pch);

	if (err_str != NULL)
		*err_str = NULL;
	return caps;
}

pcap_t *
open_capture_device_pcap_create(
#if defined(HAVE_PCAP_SET_TSTAMP_PRECISION)
    capture_options* capture_opts,
#else
    capture_options* capture_opts _U_,
#endif
    interface_options *interface_opts, int timeout,
    cap_device_open_err *open_err,
    char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
	int status;

	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "Calling pcap_create() using %s.", interface_opts->name);
	pcap_h = pcap_create(interface_opts->name, *open_err_str);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_create() returned %p.", (void *)pcap_h);
	if (pcap_h == NULL) {
		*open_err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
		return NULL;
	}
	if (interface_opts->has_snaplen) {
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "Calling pcap_set_snaplen() with snaplen %d.",
		    interface_opts->snaplen);
		pcap_set_snaplen(pcap_h, interface_opts->snaplen);
	}
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "Calling pcap_set_promisc() with promisc_mode %d.",
	    interface_opts->promisc_mode);
	pcap_set_promisc(pcap_h, interface_opts->promisc_mode);
	pcap_set_timeout(pcap_h, timeout);

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	/*
	 * If we're writing pcapng files, try to enable
	 * nanosecond-resolution capture; any code that
	 * can read pcapng files must be able to handle
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

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	if (interface_opts->timestamp_type) {
		status = pcap_set_tstamp_type(pcap_h, interface_opts->timestamp_type_id);
		/*
		 * XXX - what if it fails because that time stamp type
		 * isn't supported?
		 */
		if (status == PCAP_ERROR) {
			*open_err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
			g_strlcpy(*open_err_str, pcap_geterr(pcap_h),
			    sizeof *open_err_str);
			pcap_close(pcap_h);
			return NULL;
		}
	}
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
	status = pcap_activate(pcap_h);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_activate() returned %d.", status);
	if (status < 0) {
		/* Failed to activate, set to NULL */
		if (status == PCAP_ERROR) {
			*open_err = CAP_DEVICE_OPEN_ERR_GENERIC;
			g_strlcpy(*open_err_str, pcap_geterr(pcap_h),
			    sizeof *open_err_str);
		} else {
			if (status == PCAP_ERROR_PERM_DENIED)
				*open_err = CAP_DEVICE_OPEN_ERR_PERMISSIONS;
			else
				*open_err = CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS;
			g_strlcpy(*open_err_str, pcap_statustostr(status),
			    sizeof *open_err_str);
		}
		pcap_close(pcap_h);
		return NULL;
	}
	return pcap_h;
}
#endif /* HAVE_PCAP_CREATE */

if_capabilities_t *
get_if_capabilities_pcap_open_live(interface_options *interface_opts,
    cap_device_open_err *err, char **err_str)
{
	if_capabilities_t *caps;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pch;

	pch = pcap_open_live(interface_opts->name, MIN_PACKET_SIZE, 0, 0,
	    errbuf);
	if (pch == NULL) {
		*err = CAP_DEVICE_OPEN_ERR_GENERIC;
		*err_str = g_strdup(errbuf[0] == '\0' ? "Unknown error (pcap bug; actual error cause not reported)" : errbuf);
		return NULL;
	}

	caps = (if_capabilities_t *)g_malloc(sizeof *caps);
	caps->can_set_rfmon = FALSE;
	caps->data_link_types = get_data_link_types(pch, interface_opts,
	    err, err_str);
	if (caps->data_link_types == NULL) {
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	caps->timestamp_types = get_pcap_timestamp_types(pch, NULL);

	pcap_close(pch);

	*err_str = NULL;
	return caps;
}

pcap_t *
open_capture_device_pcap_open_live(interface_options *interface_opts,
    int timeout, cap_device_open_err *open_err,
    char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
	int snaplen;

	if (interface_opts->has_snaplen)
		snaplen = interface_opts->snaplen;
	else {
		/*
		 * Default - use the non-D-Bus maximum snapshot length of
		 * 256KB, which should be big enough (libpcap didn't get
		 * D-Bus support until after it goet pcap_create() and
		 * pcap_activate(), so we don't have D-Bus support and
		 * don't have to worry about really huge packets).
		 */
		snaplen = 256*1024;
	}
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_open_live() calling using name %s, snaplen %d, promisc_mode %d.",
	    interface_opts->name, snaplen, interface_opts->promisc_mode);
	pcap_h = pcap_open_live(interface_opts->name, snaplen,
	    interface_opts->promisc_mode, timeout, *open_err_str);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
	    "pcap_open_live() returned %p.", (void *)pcap_h);
	if (pcap_h == NULL) {
		*open_err = CAP_DEVICE_OPEN_ERR_GENERIC;
		return NULL;
	}

#ifdef _WIN32
	/* Try to set the capture buffer size. */
	if (interface_opts->buffer_size > 1) {
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
get_if_capabilities(interface_options *interface_opts,
    cap_device_open_err *err, char **err_str)
{
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
    if_capabilities_t *caps;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pch;
    int deflt;
    data_link_info_t *data_link_info;

    if (strncmp (interface_opts->name, "rpcap://", 8) == 0) {
        struct pcap_rmtauth auth;

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
		/*
		 * We don't know whether it's a permission error or not.
		 * (If it is, maybe we can give ourselves permission or
		 * maybe we just have to ask politely for permission.)
		 */
		*err = CAP_DEVICE_OPEN_ERR_GENERIC;
		*err_str = g_strdup(errbuf[0] == '\0' ? "Unknown error (pcap bug; actual error cause not reported)" : errbuf);
		return NULL;
	}

        caps = (if_capabilities_t *)g_malloc(sizeof *caps);
        caps->can_set_rfmon = FALSE;
        caps->data_link_types = NULL;
        deflt = get_pcap_datalink(pch, interface_opts->name);
        data_link_info = create_data_link_info(deflt);
        caps->data_link_types = g_list_append(caps->data_link_types, data_link_info);
	caps->timestamp_types = get_pcap_timestamp_types(pch, NULL);
        pcap_close(pch);

        *err_str = NULL;
        return caps;
    }
#endif /* defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE) */

    /*
     * Local interface.
     */
    return get_if_capabilities_local(interface_opts, err, err_str);
}

pcap_t *
open_capture_device(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    cap_device_open_err *open_err,
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
	*open_err = CAP_DEVICE_OPEN_NO_ERR;
	(*open_err_str)[0] = '\0';
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
	/*
	 * If we're opening a remote device, use pcap_open(); that's currently
	 * the only open routine that supports remote devices.
	 */
	if (strncmp (interface_opts->name, "rpcap://", 8) == 0) {
		int snaplen;

		auth.type = interface_opts->auth_type == CAPTURE_AUTH_PWD ?
		    RPCAP_RMTAUTH_PWD : RPCAP_RMTAUTH_NULL;
		auth.username = interface_opts->auth_username;
		auth.password = interface_opts->auth_password;

		if (interface_opts->has_snaplen)
			snaplen = interface_opts->snaplen;
		else {
			/*
			 * Default - use the non-D-Bus maximum snapshot length,
			 * which should be big enough, except for D-Bus.
			 */
			snaplen = 256*1024;
		}
		g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
		    "Calling pcap_open() using name %s, snaplen %d, promisc_mode %d, datatx_udp %d, nocap_rpcap %d.",
		    interface_opts->name, snaplen,
		    interface_opts->promisc_mode, interface_opts->datatx_udp,
		    interface_opts->nocap_rpcap);
		pcap_h = pcap_open(interface_opts->name, snaplen,
		    /* flags */
		    (interface_opts->promisc_mode ? PCAP_OPENFLAG_PROMISCUOUS : 0) |
		    (interface_opts->datatx_udp ? PCAP_OPENFLAG_DATATX_UDP : 0) |
		    (interface_opts->nocap_rpcap ? PCAP_OPENFLAG_NOCAPTURE_RPCAP : 0),
		    timeout, &auth, *open_err_str);
		if (pcap_h == NULL) {
			/*
			 * Error.
			 *
			 * We don't know whether it's a permission error
			 * or not.
			 * (If it is, maybe we can give ourselves permission
			 * or maybe we just have to ask politely for
			 * permission.)
			 */
			*open_err = CAP_DEVICE_OPEN_ERR_GENERIC;
			/* Did pcap actually supply an error message? */
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
	    timeout, open_err, open_err_str);
	g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "open_capture_device %s : %s", pcap_h ? "SUCCESS" : "FAILURE", interface_opts->name);
	return pcap_h;
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
