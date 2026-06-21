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
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPCHILD

#ifdef HAVE_LIBPCAP

#include <wireshark.h>

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

#include "capture/capture_ifinfo.h"
#include "capture/capture-pcap-util.h"
#include "capture/capture-pcap-util-int.h"
#ifdef _WIN32
#include "capture/capture-wpcap.h"
#else
#define ws_pcap_findalldevs_ex pcap_findalldevs_ex
#endif

#include <wsutil/file_util.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>

#ifdef _WIN32
#include "capture/capture_win_ifnames.h" /* windows friendly interface names */
#endif

#ifdef _WIN32
#include <iphlpapi.h>
#include "capture/capture_win_ifnames.h" /* windows friendly interface names */

static interface_type
get_windows_iftype(const char *name)
{
	ULONG buflen = 15000;
	PIP_ADAPTER_ADDRESSES addrs, curr;
	ULONG ret;
	interface_type type = IF_WIRED;

	addrs = (PIP_ADAPTER_ADDRESSES)g_malloc(buflen);
	ret = GetAdaptersAddresses(AF_UNSPEC,
	    GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &buflen);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		g_free(addrs);
		addrs = (PIP_ADAPTER_ADDRESSES)g_malloc(buflen);
		ret = GetAdaptersAddresses(AF_UNSPEC,
		    GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &buflen);
	}
	if (ret != NO_ERROR) {
		g_free(addrs);
		return IF_WIRED;
	}

	/*
	 * Npcap device names use \Device\NPF_{GUID}, so
	 * strip that prefix and match against AdapterName
	 * which is the {GUID} part.
	 */
	const char *match_name = name;
	if (strncmp(name, "\\Device\\NPF_", 12) == 0)
		match_name = name + 12;

	for (curr = addrs; curr != NULL; curr = curr->Next) {
		if (g_ascii_strcasecmp(curr->AdapterName,
		    match_name) != 0)
			continue;

		switch (curr->IfType) {
		case IF_TYPE_SOFTWARE_LOOPBACK:
			type = IF_LOOPBACK;
			break;
		case IF_TYPE_TUNNEL:
			type = IF_TUNNEL;
			break;
		case IF_TYPE_PPP:
			type = IF_DIALUP;
			break;
		case IF_TYPE_IEEE80211:
			type = IF_WIRELESS;
			break;
		case IF_TYPE_PROP_VIRTUAL:
			type = IF_VIRTUAL;
			break;
		default:
			break;
		}
		break;
	}

	g_free(addrs);
	return type;
}
#else /* _WIN32 */
/*
 * Not Windows (UN*Xes, Haiku)
 *
 * Get stuff for various socket ioctls.
 */
#include <sys/ioctl.h>

/*
 * Needed for the code to get a device description.
 */
#include <errno.h>

#include <ifaddrs.h>
#include <unistd.h>

/*
 * On most supported platforms <sys/ioctl.h> also defines the SIOCGIF* macros.
 * However, on Haiku and Solaris/Illumos the macros need <sys/sockio.h>,
 * which does not exist on some other systems.
 */
#if defined(__HAIKU__) || defined(sun) || defined(_sun)
#include <sys/sockio.h>
#endif

/*
 * On Linux, <net/if.h> must be included before anything that pulls in
 * <linux/if.h> (e.g. <linux/if_bonding.h> below); otherwise glibc's
 * libc-compat guard cannot suppress the kernel-header definitions and
 * we get redefinition errors for IFF_UP and friends.
 */
#include <net/if.h>

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
#if defined(__linux__)

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_LINUX_IF_BONDING_H
#include <linux/if_bonding.h>
#endif

/*
 * If we're building for a Linux version that supports bonding,
 * define HAVE_BONDING.
 */
#if defined(BOND_INFO_QUERY_OLD) || defined(SIOCBONDINFOQUERY)
#define HAVE_BONDING
#endif

#endif /* defined(__linux__) */

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <net/if_dl.h>
#endif

#include <netinet/in.h>

/*
 * Given an interface name, find the "friendly name" and interface
 * type for the interface.
 */

static int get_unix_iff_flags(const char *ifname)
{
	int sock;
	struct ifreq ifr;
	size_t len;

	if (ifname == NULL)
		return -1;

	len = strlen(ifname);
	if (len == 0 || len >= IFNAMSIZ)
		return -1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, ifname, len);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		close(sock);
		return -1;
	}

	close(sock);
	return ifr.ifr_flags;
}

/*
 * Returns the sdl_type (IANA ifType) for the given interface name,
 * or -1 if not found.
 */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
static int get_unix_sdl_type(const char *ifname)
{
	struct ifaddrs *ifap, *ifa;
	int type = -1;

	if (ifname == NULL)
		return -1;

	if (getifaddrs(&ifap) != 0)
		return -1;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		type = sdl->sdl_type;
		break;
	}

	freeifaddrs(ifap);
	return type;
}
#else /* defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) */
static int get_unix_sdl_type(const char *ifname _U_)
{
	return -1;
}
#endif /* defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) */

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
	wireless_path = ws_strdup_printf("/sys/class/net/%s/wireless", name);
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
#endif /* _WIN32 */

static if_info_t *
if_info_new(const char *name, const char *description, bool loopback);

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
	(void) g_strlcpy(ifrdesc.ifr_name, name, sizeof ifrdesc.ifr_name);
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
					snprintf(description, descr_size,
					    "%s%ld", descr_prefix, busnum);
				}
			}
		}
	}
#endif /* __FreeBSD__ */
#endif /* SIOCGIFDESCR */
	if_info = if_info_new(name, description, false);
	g_free(description);
	return if_info;
}

if_addr_t *
if_addr_copy(const if_addr_t *addr)
{
	if_addr_t *new_addr = g_new(if_addr_t, 1);
	new_addr->ifat_type = addr->ifat_type;
	switch (addr->ifat_type) {
	case IF_AT_IPv4:
		new_addr->addr.ip4_addr = addr->addr.ip4_addr;
		break;
	case IF_AT_IPv6:
		memcpy(new_addr->addr.ip6_addr, addr->addr.ip6_addr, sizeof(addr->addr));
		break;
	default:
		/* In case we add non-IP addresses */
		break;
	}
	return new_addr;
}

static void*
if_addr_copy_cb(const void *data, void *user_data _U_)
{
	return if_addr_copy((const if_addr_t*)data);
}

void
if_info_free(if_info_t *if_info)
{
	if (if_info == NULL) {
		return;
	}
	g_free(if_info->name);
	g_free(if_info->friendly_name);
	g_free(if_info->vendor_description);
	g_free(if_info->extcap);
	g_slist_free_full(if_info->addrs, g_free);
	if (if_info->caps) {
		free_if_capabilities(if_info->caps);
	}
	g_free(if_info);
}

static void*
copy_linktype_cb(const void *data, void *user_data _U_)
{
	const data_link_info_t *linktype_info = (const data_link_info_t *)data;

	data_link_info_t *ret = g_new(data_link_info_t, 1);
	ret->dlt = linktype_info->dlt;
	ret->name = g_strdup(linktype_info->name);
	ret->description = g_strdup(linktype_info->description);
	return ret;
}

static void*
copy_timestamp_cb(const void *data, void *user_data _U_)
{
	const timestamp_info_t *timestamp_info = (const timestamp_info_t *)data;

	timestamp_info_t *ret = g_new(timestamp_info_t, 1);
	ret->name = g_strdup(timestamp_info->name);
	ret->description = g_strdup(timestamp_info->description);
	return ret;
}

static if_capabilities_t *
if_capabilities_copy(const if_capabilities_t *caps)
{
	if (caps == NULL) return NULL;

	if_capabilities_t *ret = g_new(if_capabilities_t, 1);
	ret->can_set_rfmon = caps->can_set_rfmon;
	ret->data_link_types = g_list_copy_deep(caps->data_link_types, copy_linktype_cb, NULL);
	ret->timestamp_types = g_list_copy_deep(caps->timestamp_types, copy_timestamp_cb, NULL);
	ret->data_link_types_rfmon = g_list_copy_deep(caps->data_link_types_rfmon, copy_linktype_cb, NULL);
	ret->primary_msg = g_strdup(caps->primary_msg);
	ret->secondary_msg = caps->secondary_msg;

	return ret;
}

if_info_t *
if_info_copy(const if_info_t *if_info)
{
	if_info_t *new_if_info;
	new_if_info = g_new(if_info_t, 1);
	new_if_info->name = g_strdup(if_info->name);
	/* g_strdup accepts NULL as input and returns NULL. */
	new_if_info->friendly_name = g_strdup(if_info->friendly_name);
	new_if_info->vendor_description = g_strdup(if_info->vendor_description);
	new_if_info->addrs = g_slist_copy_deep(if_info->addrs, if_addr_copy_cb, NULL);
	new_if_info->type = if_info->type;
	new_if_info->loopback = if_info->loopback;
	new_if_info->extcap = g_strdup(if_info->extcap);
	new_if_info->caps = if_capabilities_copy(if_info->caps);

	return new_if_info;
}

static void*
if_info_copy_cb(const void* data, void *user_data _U_)
{
	return if_info_copy((const if_info_t*)data);
}

static if_info_t *
if_info_new(const char *name, const char *description, bool loopback)
{
	if_info_t *if_info;
#ifdef _WIN32
	const char *guid_text;
	GUID guid;
#endif

	if_info = g_new(if_info_t, 1);
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
	if_info->type = get_windows_iftype(name);

	/*
	 * Refine with description string matching for cases
	 * where IfType is too generic (e.g. TAP adapters
	 * reporting as IF_TYPE_ETHERNET_CSMACD).
	 */
	if (if_info->type == IF_WIRED) {
		if (description && (strstr(description, "generic dialup") != NULL ||
		    strstr(description, "PPP/SLIP") != NULL))
			if_info->type = IF_DIALUP;
		else if (description && (strstr(description, "Wireless") != NULL ||
		    strstr(description, "802.11") != NULL))
			if_info->type = IF_WIRELESS;
		else if (description && (strstr(description, "AirPcap") != NULL ||
		    strstr(name, "airpcap") != NULL))
			if_info->type = IF_AIRPCAP;
		else if (description && strstr(description, "Bluetooth") != NULL)
			if_info->type = IF_BLUETOOTH;
		else if (description && (strstr(description, "VMware") != NULL ||
		    strstr(description, "VirtualBox") != NULL ||
		    strstr(description, "Hyper-V") != NULL))
			if_info->type = IF_VIRTUAL;
		else if (description && (strstr(description, "WireGuard") != NULL ||
		    strstr(description, "TAP-Windows") != NULL ||
		    strstr(description, "Wintun") != NULL))
			if_info->type = IF_TUNNEL;
	}

	/*
	 * On Windows, the "description" is a vendor description,
	 * and the friendly name isn't returned by Npcap.
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
		 * provided by Npcap, and there is no vendor
		 * description.
		 */
		if_info->friendly_name = g_strdup(description);
		if_info->vendor_description = NULL;
	}
#else /* _WIN32 */
	/*
	 * On UN*X, if there is a description, it's a friendly
	 * name, and there is no vendor description.
	 *
	 * Try the platform's way of getting a friendly name and
	 * interface type first.
	 *
	 * If that fails, then try to figure out what the interface
	 * is and give it a friendly name and appropriate type.
	 */
	add_unix_interface_ifinfo(if_info, name, description);
	if (if_info->type == IF_WIRED) {
		int flags = get_unix_iff_flags(name);
		int sdl_type = get_unix_sdl_type(name);

		if (flags != -1 && (flags & IFF_LOOPBACK)) {
			if_info->type = IF_LOOPBACK;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Loopback");
		} else if (flags != -1 && (flags & IFF_POINTOPOINT)) {
			/*
			 * XXX - what about pppN interfaces?
			 * They're just PPP links, not tunnels.
			 */
			if_info->type = IF_TUNNEL;
			if (if_info->friendly_name == NULL) {
#if defined(__APPLE__)
				if (g_ascii_strncasecmp(name, "utun", 4) == 0)
					if_info->friendly_name = g_strdup("Tunnel (System Services, VPN)");
				else if (g_ascii_strncasecmp(name, "ipsec", 5) == 0)
					if_info->friendly_name = g_strdup("IPsec Tunnel");
#elif defined(__linux__)
				if (g_ascii_strncasecmp(name, "wg", 2) == 0)
					if_info->friendly_name = g_strdup("WireGuard Tunnel");
				else if (g_ascii_strncasecmp(name, "gre", 3) == 0)
					if_info->friendly_name = g_strdup("GRE Tunnel");
				else if (g_ascii_strncasecmp(name, "sit", 3) == 0)
					if_info->friendly_name = g_strdup("IPv6-in-IPv4 Tunnel");
				else if (g_ascii_strncasecmp(name, "ip6tnl", 6) == 0)
					if_info->friendly_name = g_strdup("IPv6 Tunnel");
				else if (g_ascii_strncasecmp(name, "ip6gre", 6) == 0)
					if_info->friendly_name = g_strdup("IPv6 GRE Tunnel");
				else if (g_ascii_strncasecmp(name, "tun", 3) == 0)
					if_info->friendly_name = g_strdup("TUN Tunnel (VPN)");
				else if (g_ascii_strncasecmp(name, "tap", 3) == 0)
					if_info->friendly_name = g_strdup("TAP Tunnel (VPN)");
#endif
				if (if_info->friendly_name == NULL)
					if_info->friendly_name = g_strdup("Tunnel");
			}
		} else if (sdl_type == 0x37) {
			if_info->type = IF_TUNNEL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("GIF Tunnel");
		} else if (sdl_type == 0x39) {
			if_info->type = IF_TUNNEL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("6to4 Tunnel");
		} else if (g_ascii_strncasecmp(name, "vmnet", 5) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("VMware Virtual Network");
		} else if (g_ascii_strncasecmp(name, "vmxnet", 6) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("VMware Paravirtual NIC");
#if defined(__APPLE__)
		} else if (g_ascii_strncasecmp(name, "awdl", 4) == 0) {
			if_info->type = IF_WIRELESS;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Apple Wireless Direct Link");
		} else if (g_ascii_strncasecmp(name, "llw", 3) == 0) {
			if_info->type = IF_WIRELESS;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Low-Latency WLAN");
		} else if (g_ascii_strncasecmp(name, "ap", 2) == 0 &&
			   g_ascii_isdigit(name[2])) {
			if_info->type = IF_WIRELESS;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Wi-Fi Access Point");
		} else if (g_ascii_strncasecmp(name, "anpi", 4) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Apple Network Peer Injection");
		} else if (g_ascii_strncasecmp(name, "bridge", 6) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Bridge");
		} else if (g_ascii_strncasecmp(name, "vmenet", 6) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("VM Ethernet");
#elif defined(__linux__)
		} else if (g_ascii_strncasecmp(name, "docker", 6) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Docker Bridge");
		} else if (g_ascii_strncasecmp(name, "veth", 4) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Virtual Ethernet");
		} else if (strncmp(name, "br-", 3) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Bridge");
		} else if (g_ascii_strncasecmp(name, "virbr", 5) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Libvirt Bridge");
		} else if (g_ascii_strncasecmp(name, "lxcbr", 5) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("LXC Bridge");
		} else if (g_ascii_strncasecmp(name, "nlmon", 5) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Netlink monitor");
		} else if (g_ascii_strncasecmp(name, "nflog", 5) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Netfilter log");
		} else if (g_ascii_strncasecmp(name, "nfqueue", 7) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("Netfilter queue");
		} else if (g_ascii_strncasecmp(name, "dbus-session", 12) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("D-Bus session bus");
		} else if (g_ascii_strncasecmp(name, "dbus-system", 11) == 0) {
			if_info->type = IF_VIRTUAL;
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("D-Bus system bus");
#endif
		}
	}
#if defined(__linux__)
	if (if_info->type == IF_USB) {
		if (g_ascii_strncasecmp(name, "usbmon0", 7) == 0) {
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("USB monitor (all)");
		} else if (g_ascii_strncasecmp(name, "usbmon", 6) == 0) {
			if (if_info->friendly_name == NULL)
				if_info->friendly_name = g_strdup("USB monitor");
		}
	}
#endif

	if_info->vendor_description = NULL;
#endif /* _WIN32 */
	if_info->loopback = loopback;
	if_info->addrs = NULL;
	if_info->caps = NULL;
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
		if_addr->addr.ip4_addr = ai->sin_addr.s_addr;
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
get_remote_interface_list_common(const char *hostname, const char *port,
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
		if (strcmp(errbuf, "not supported") == 0) {
			/*
			 * macOS 14's pcap_createsrcstr(), which is a
			 * stub that always returns -1 with an error
			 * message of "not supported".
			 *
			 * In this case, as we passed it an rpcap://
			 * URL, treat that as meaning "remote capture
			 * not supported".
			 */
			g_strlcpy(errbuf, "Remote capture not supported",
			    PCAP_ERRBUF_SIZE);
		}
		if (err_str != NULL)
			*err_str = cant_get_if_list_error_message(errbuf);
		return NULL;
	}

	auth.type = auth_type;
	auth.username = g_strdup(username);
	auth.password = g_strdup(passwd);

	if (ws_pcap_findalldevs_ex(source, &auth, &alldevs, errbuf) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		if (strcmp(errbuf, "not supported") == 0) {
			/*
			 * macOS 14's pcap_findalldevs_ex(), which is a
			 * stub that always returns -1 with an error
			 * message of "not supported".
			 *
			 * In this case, as we passed it an rpcap://
			 * URL, treat that as meaning "remote capture
			 * not supported".
			 */
			g_strlcpy(errbuf, "Remote capture not supported",
			    PCAP_ERRBUF_SIZE);
		}
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
		    (dev->flags & PCAP_IF_LOOPBACK) ? true : false);
		il = g_list_append(il, if_info);
		if_info_ip(if_info, dev);
	}
	pcap_freealldevs(alldevs);
	g_free(auth.username);
	g_free(auth.password);

	return il;
}
#endif /* HAVE_PCAP_REMOTE */

GList *
get_local_interface_list(int *err, char **err_str)
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
		    (dev->flags & PCAP_IF_LOOPBACK) ? true : false);
		il = g_list_append(il, if_info);
		if_info_ip(if_info, dev);
	}
	pcap_freealldevs(alldevs);

	return il;
}

GList*
get_local_interface_list_ss(int* err, char** err_str)
{
	/*
	 * This is for Stratoshark/strato, so we don't look for
	 * intrfaces.
	 */
	*err = 0;
	if (err_str != NULL)
		*err_str = NULL;
	return NULL;
}

static void
free_if_cb(void * data, void * user_data _U_)
{
	if_info_free((if_info_t *)data);
}

void
free_interface_list(GList *if_list)
{
	g_list_foreach(if_list, free_if_cb, NULL);
	g_list_free(if_list);
}

GList*
interface_list_copy(GList *if_list)
{
	return g_list_copy_deep(if_list, if_info_copy_cb, NULL);
}

static void
free_linktype_cb(void * data)
{
	data_link_info_t *linktype_info = (data_link_info_t *)data;

	g_free(linktype_info->name);
	g_free(linktype_info->description);
	g_free(linktype_info);
}

static void
free_timestamp_cb(void * data)
{
	timestamp_info_t *timestamp_info = (timestamp_info_t *)data;

	g_free(timestamp_info->name);
	g_free(timestamp_info->description);
	g_free(data);
}

void
free_if_capabilities(if_capabilities_t *caps)
{
	g_list_free_full(caps->data_link_types, free_linktype_cb);
	g_list_free_full(caps->data_link_types_rfmon, free_linktype_cb);

	g_list_free_full(caps->timestamp_types, free_timestamp_cb);

	g_free(caps->primary_msg);

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
#endif /* _AIX */

	return datalink;
}

/* Set the data link type on a pcap. */
bool
set_pcap_datalink(pcap_t *pcap_h, int datalink, char *name,
    char *errmsg, size_t errmsg_len,
    char *secondary_errmsg, size_t secondary_errmsg_len)
{
	char *set_datalink_err_str;

	if (datalink == -1)
		return true; /* just use the default */
	if (pcap_set_datalink(pcap_h, datalink) == 0)
		return true; /* no error */
	set_datalink_err_str = pcap_geterr(pcap_h);
	snprintf(errmsg, errmsg_len, "Unable to set data link type on interface '%s' (%s).",
	    name, set_datalink_err_str);
	/*
	 * If the error isn't "XXX is not one of the DLTs supported by this device",
	 * tell the user to tell the Wireshark developers about it.
	 */
	if (strstr(set_datalink_err_str, "is not one of the DLTs supported by this device") == NULL)
		snprintf(secondary_errmsg, secondary_errmsg_len,
		           "%s", please_report_bug());
	else
		secondary_errmsg[0] = '\0';
	return false;
}

static data_link_info_t *
create_data_link_info(int dlt)
{
	data_link_info_t *data_link_info;
	const char *text;

	data_link_info = g_new(data_link_info_t, 1);
	data_link_info->dlt = dlt;
	text = pcap_datalink_val_to_name(dlt);
	if (text != NULL)
		data_link_info->name = g_strdup(text);
	else
		data_link_info->name = ws_strdup_printf("DLT %d", dlt);
	text = pcap_datalink_val_to_description(dlt);
	data_link_info->description = g_strdup(text);
	return data_link_info;
}

static GList *
get_data_link_types(pcap_t *pch, interface_options *interface_opts,
    cap_device_open_status *status, char **status_str)
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
		/*
		 * If we have pcap_create(), we have
		 * pcap_statustostr(), and we can get back errors
		 * other than PCAP_ERROR (-1), such as
		 * PCAP_ERROR_NOT_ACTIVATED. and we should report
		 * them properly.
		 */
		switch (nlt) {

		case PCAP_ERROR:
			*status = CAP_DEVICE_OPEN_ERROR_OTHER;
			*status_str = ws_strdup_printf("pcap_list_datalinks() failed: %s",
			    pcap_geterr(pch));
			break;

		default:
			/*
			 * This "shouldn't happen".
			 */
			*status = CAP_DEVICE_OPEN_ERROR_OTHER;
			*status_str = ws_strdup_printf("pcap_list_datalinks() failed: %s - %s",
			    pcap_statustostr(nlt), pcap_geterr(pch));
			break;
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
	pcap_free_datalinks(linktypes);

	*status_str = NULL;
	return data_link_types;
}

/* Get supported timestamp types for a libpcap device.  */
static GList*
get_pcap_timestamp_types(pcap_t *pch _U_, char **err_str _U_)
{
	GList *list = NULL;
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
	return list;
}

/*
 * Request high-resolution time stamps.
 *
 * If this fails with PCAP_ERROR_TSTAMP_PRECISION_NOTSUP, that means
 * that boring old microsecond-resolution time stamps are all that
 * are supported, so we just live with that.
 */
static int
request_high_resolution_timestamp(pcap_t *pcap_h)
{
	int status;

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
	 *
	 * XXX - This shouldn't be needed anymore; we don't support running
	 * on any release older than macOS 11, and starting with macOS 11 the
	 * system libpcap is based on libpcap 1.5 or later and has
	 * pcap_set_tstamp_precision().
	 */
	static bool initialized = false;
	static int (*p_pcap_set_tstamp_precision)(pcap_t *, int);

	if (!initialized) {
		p_pcap_set_tstamp_precision =
		    (int (*)(pcap_t *, int))
		      dlsym(RTLD_NEXT, "pcap_set_tstamp_precision");
		initialized = true;
	}
	if (p_pcap_set_tstamp_precision != NULL) {
		status = (*p_pcap_set_tstamp_precision)(pcap_h,
		    PCAP_TSTAMP_PRECISION_NANO);
	} else {
		/*
		 * Older libpcap, which doesn't have support
		 * for setting the time stamp resolution.
		 */
		status = PCAP_ERROR_TSTAMP_PRECISION_NOTSUP;
	}
#else /* __APPLE__ */
	/*
	 * On other UN*Xes we require that we be run on an OS version
	 * with a libpcap equal to or later than the version with which
	 * we were built.
	 */
	status = pcap_set_tstamp_precision(pcap_h, PCAP_TSTAMP_PRECISION_NANO);
#endif /* __APPLE__ */
	if (status == PCAP_ERROR_TSTAMP_PRECISION_NOTSUP) {
		/* This isn't a fatal error. */
		status = 0;
	}
	return status;
}

/*
 * Return true if the pcap_t in question is set up for high-precision
 * time stamps, false otherwise.
 */
bool
have_high_resolution_timestamp(pcap_t *pcap_h)
{
#ifdef __APPLE__
	/*
	 * See above.
	 */
	static bool initialized = false;
	static int (*p_pcap_get_tstamp_precision)(pcap_t *);

	if (!initialized) {
		p_pcap_get_tstamp_precision =
		    (int (*)(pcap_t *))
		      dlsym(RTLD_NEXT, "pcap_get_tstamp_precision");
		initialized = true;
	}
	if (p_pcap_get_tstamp_precision != NULL)
		return (*p_pcap_get_tstamp_precision)(pcap_h) == PCAP_TSTAMP_PRECISION_NANO;
	else
		return false;	/* Can't get implies couldn't set */
#else /* __APPLE__ */
	/*
	 * On other UN*Xes we require that we be run on an OS version
	 * with a libpcap equal to or later than the version with which
	 * we were built.
	 */
	return pcap_get_tstamp_precision(pcap_h) == PCAP_TSTAMP_PRECISION_NANO;
#endif /* __APPLE__ */
}

#ifdef HAVE_BONDING
static bool
is_linux_bonding_device(const char *ifname)
{
	int fd;
	struct ifreq ifr;
	ifbond ifb;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return false;

	memset(&ifr, 0, sizeof ifr);
	(void) g_strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
	memset(&ifb, 0, sizeof ifb);
	ifr.ifr_data = (caddr_t)&ifb;
#if defined(SIOCBONDINFOQUERY)
	if (ioctl(fd, SIOCBONDINFOQUERY, &ifr) == 0) {
		close(fd);
		return true;
	}
#else
	if (ioctl(fd, BOND_INFO_QUERY_OLD, &ifr) == 0) {
		close(fd);
		return true;
	}
#endif

	close(fd);
	return false;
}
#else /* HAVE_BONDING */
static bool
is_linux_bonding_device(const char *ifname _U_)
{
	return false;
}
#endif /* HAVE_BONDING */

if_capabilities_t *
get_if_capabilities_pcap_create(interface_options *interface_opts,
    cap_device_open_status *open_status, char **open_status_str)
{
	if_capabilities_t *caps;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pch;
	int status;

	pch = pcap_create(interface_opts->name, errbuf);
	if (pch == NULL) {
		*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
		*open_status_str = g_strdup(errbuf);
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
		switch (status) {

		case PCAP_ERROR_NO_SUCH_DEVICE:
			*open_status = CAP_DEVICE_OPEN_ERROR_NO_SUCH_DEVICE;
			*open_status_str = ws_strdup_printf("pcap_can_set_rfmon() failed: %s",
			    pcap_geterr(pch));
			break;

		case PCAP_ERROR_PERM_DENIED:
			*open_status = CAP_DEVICE_OPEN_ERROR_PERM_DENIED;
			*open_status_str = ws_strdup_printf("pcap_can_set_rfmon() failed: %s",
			    pcap_geterr(pch));
			break;

		case PCAP_ERROR:
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			*open_status_str = ws_strdup_printf("pcap_can_set_rfmon() failed: %s",
			    pcap_geterr(pch));
			break;

		default:
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			*open_status_str = ws_strdup_printf("pcap_can_set_rfmon() failed: %s - %s",
			    pcap_statustostr(status), pcap_geterr(pch));
			break;
		}
		pcap_close(pch);
		return NULL;
	}
	caps = (if_capabilities_t *)g_malloc0(sizeof *caps);
	if (status == 0)
		caps->can_set_rfmon = false;
	else if (status == 1) {
		caps->can_set_rfmon = true;
		if (interface_opts->monitor_mode) {
			status = pcap_set_rfmon(pch, 1);
			if (status < 0) {
				/*
				 * This "should not happen".
				 */
				*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
				*open_status_str = ws_strdup_printf("pcap_set_rfmon() returned %d",
				    status);
				pcap_close(pch);
				g_free(caps);
				return NULL;
			}
		}
	} else {
		/*
		 * This "should not happen".
		 */
		*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
		*open_status_str = ws_strdup_printf("pcap_can_set_rfmon() returned %d",
		    status);
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	status = pcap_activate(pch);
	if (status < 0) {
		/* Error. */
		switch (status) {

		case PCAP_ERROR_NO_SUCH_DEVICE:
			*open_status = CAP_DEVICE_OPEN_ERROR_NO_SUCH_DEVICE;
			*open_status_str = ws_strdup_printf("pcap_activate() failed: %s",
			    pcap_geterr(pch));
			break;

		case PCAP_ERROR_PERM_DENIED:
			*open_status = CAP_DEVICE_OPEN_ERROR_PERM_DENIED;
			*open_status_str = ws_strdup_printf("pcap_activate() failed: %s",
			    pcap_geterr(pch));
			break;

		case PCAP_ERROR_IFACE_NOT_UP:
			*open_status = CAP_DEVICE_OPEN_ERROR_IFACE_NOT_UP;
			*open_status_str = ws_strdup_printf("pcap_activate() failed: %s",
			    pcap_geterr(pch));
			break;

		case PCAP_ERROR:
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			*open_status_str = ws_strdup_printf("pcap_activate() failed: %s",
			    pcap_geterr(pch));
			break;

		default:
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			*open_status_str = ws_strdup_printf("pcap_activate() failed: %s - %s",
			    pcap_statustostr(status), pcap_geterr(pch));
			break;
		}
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}

	caps->data_link_types = get_data_link_types(pch, interface_opts,
	    open_status, open_status_str);
	if (caps->data_link_types == NULL) {
		pcap_close(pch);
		g_free(caps);
		return NULL;
	}
	if (interface_opts->monitor_mode) {
		caps->data_link_types_rfmon = caps->data_link_types;
		caps->data_link_types = NULL;
	}

	caps->timestamp_types = get_pcap_timestamp_types(pch, NULL);

	pcap_close(pch);

	*open_status = CAP_DEVICE_OPEN_NO_ERR;
	*open_status_str = NULL;
	return caps;
}

static void
set_open_status_str(int status, pcap_t *pcap_h,
    char (*open_status_str)[PCAP_ERRBUF_SIZE])
{
	switch (status) {

	case PCAP_ERROR:
		(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
		    sizeof *open_status_str);
		break;

	default:
		(void) g_strlcpy(*open_status_str, pcap_statustostr(status),
		    sizeof *open_status_str);
		break;
	}
}

pcap_t *
open_capture_device_pcap_create(
    capture_options* capture_opts _U_,
    interface_options *interface_opts, int timeout,
    cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
	int status;

	ws_debug("Calling pcap_create() using %s.", interface_opts->name);
	pcap_h = pcap_create(interface_opts->name, *open_status_str);
	ws_debug("pcap_create() returned %p.", (void *)pcap_h);
	if (pcap_h == NULL) {
		*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
		return NULL;
	}
	if (interface_opts->has_snaplen) {
		ws_debug("Calling pcap_set_snaplen() with snaplen %d.",
		    interface_opts->snaplen);
		status = pcap_set_snaplen(pcap_h, interface_opts->snaplen);
		if (status < 0) {
			/* Error. */
			set_open_status_str(status, pcap_h, open_status_str);
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			pcap_close(pcap_h);
			return NULL;
		}
	}
	ws_debug("Calling pcap_set_promisc() with promisc_mode %d.",
	    interface_opts->promisc_mode);
	status = pcap_set_promisc(pcap_h, interface_opts->promisc_mode);
	if (status < 0) {
		/* Error. */
		set_open_status_str(status, pcap_h, open_status_str);
		*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
		pcap_close(pcap_h);
		return NULL;
	}
	status = pcap_set_timeout(pcap_h, timeout);
	if (status < 0) {
		/* Error. */
		set_open_status_str(status, pcap_h, open_status_str);
		*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
		pcap_close(pcap_h);
		return NULL;
	}

	/*
	 * Try to enable nanosecond-resolution capture; any code
	 * that can read pcapng files must be able to handle
	 * nanosecond-resolution time stamps. We think at this
	 * point that code that reads pcap files should recognize
	 * the nanosecond-resolution pcap file magic number. If
	 * it doesn't, we can downconvert via a program that
	 * uses libwiretap.
	 *
	 * We don't care whether this succeeds or fails; if it
	 * fails (because we don't have pcap_set_tstamp_precision(),
	 * or because we do but the OS or device doesn't support
	 * nanosecond resolution timing), we just use the microsecond-
	 * resolution time stamps we get.
	 */
	status = request_high_resolution_timestamp(pcap_h);
	if (status < 0) {
		/* Error. */
		set_open_status_str(status, pcap_h, open_status_str);
		*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
		pcap_close(pcap_h);
		return NULL;
	}

	if (interface_opts->timestamp_type) {
		status = pcap_set_tstamp_type(pcap_h, interface_opts->timestamp_type_id);
		/*
		 * XXX - what if it fails because that time stamp type
		 * isn't supported?
		 */
		if (status < 0) {
			set_open_status_str(status, pcap_h, open_status_str);
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			pcap_close(pcap_h);
			return NULL;
		}
	}

	ws_debug("buffersize %d.", interface_opts->buffer_size);
	if (interface_opts->buffer_size != 0) {
		status = pcap_set_buffer_size(pcap_h,
		    interface_opts->buffer_size * 1024 * 1024);
		if (status < 0) {
			set_open_status_str(status, pcap_h, open_status_str);
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			pcap_close(pcap_h);
			return NULL;
		}
	}
	ws_debug("monitor_mode %d.", interface_opts->monitor_mode);
	if (interface_opts->monitor_mode) {
		status = pcap_set_rfmon(pcap_h, 1);
		if (status < 0) {
			set_open_status_str(status, pcap_h, open_status_str);
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			pcap_close(pcap_h);
			return NULL;
		}
	}
	status = pcap_activate(pcap_h);
	ws_debug("pcap_activate() returned %d.", status);
	if (status < 0) {
		/* Failed to activate, set to NULL */
		switch (status) {

		case PCAP_ERROR_NO_SUCH_DEVICE:
			*open_status = CAP_DEVICE_OPEN_ERROR_NO_SUCH_DEVICE;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_ERROR_PERM_DENIED:
			*open_status = CAP_DEVICE_OPEN_ERROR_PERM_DENIED;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_ERROR_PROMISC_PERM_DENIED:
			*open_status = CAP_DEVICE_OPEN_ERROR_PROMISC_PERM_DENIED;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_ERROR_RFMON_NOTSUP:
			*open_status = CAP_DEVICE_OPEN_ERROR_RFMON_NOTSUP;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_ERROR_IFACE_NOT_UP:
			*open_status = CAP_DEVICE_OPEN_ERROR_IFACE_NOT_UP;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_ERROR:
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		default:
			*open_status = CAP_DEVICE_OPEN_ERROR_OTHER;
			snprintf(*open_status_str, sizeof *open_status_str,
			    "%s - %s", pcap_statustostr(status), pcap_geterr(pcap_h));
			break;
		}
		pcap_close(pcap_h);
		return NULL;
	}
	if (status > 0) {
		/*
		 * Warning.  The call succeeded, but something happened
		 * that the user might want to know.
		 */
		switch (status) {

		case PCAP_WARNING_PROMISC_NOTSUP:
			*open_status = CAP_DEVICE_OPEN_WARNING_PROMISC_NOTSUP;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
			*open_status = CAP_DEVICE_OPEN_WARNING_TSTAMP_TYPE_NOTSUP;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		case PCAP_WARNING:
			*open_status = CAP_DEVICE_OPEN_WARNING_OTHER;
			(void) g_strlcpy(*open_status_str, pcap_geterr(pcap_h),
			    sizeof *open_status_str);
			break;

		default:
			*open_status = CAP_DEVICE_OPEN_WARNING_OTHER;
			snprintf(*open_status_str, sizeof *open_status_str,
			    "%s - %s", pcap_statustostr(status), pcap_geterr(pcap_h));
			break;
		}
	} else {
		/*
		 * No warning issued.
		 */
		*open_status = CAP_DEVICE_OPEN_NO_ERR;
	}
	return pcap_h;
}

/*
 * Get the capabilities of a network device.
 */
if_capabilities_t *
get_if_capabilities(interface_options *interface_opts,
    cap_device_open_status *status, char **status_str)
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
		 * And, if it is, the user will either have to ask for
		 * permission for their own remote account or will have
		 * to use an account that *does* have permissions.
		 */
		*status = CAP_DEVICE_OPEN_ERROR_GENERIC;
		if (strcmp(errbuf, "not supported") == 0) {
			/*
			 * macOS 14's pcap_open(), which is a stub that
			 * always returns NULL with an error message of
			 * "not supported".
			 *
			 * In this case, as we passed it an rpcap://
			 * URL, treat that as meaning "remote capture
			 * not supported".
			 */
			(void) g_strlcpy(errbuf, "Remote capture not supported",
			    PCAP_ERRBUF_SIZE);
		}
		*status_str = g_strdup(errbuf[0] == '\0' ? "Unknown error (pcap bug; actual error cause not reported)" : errbuf);
		return NULL;
	}

        caps = (if_capabilities_t *)g_malloc0(sizeof *caps);
        caps->can_set_rfmon = false;
        caps->data_link_types = NULL;
        deflt = get_pcap_datalink(pch, interface_opts->name);
        data_link_info = create_data_link_info(deflt);
        caps->data_link_types = g_list_append(caps->data_link_types, data_link_info);
	caps->timestamp_types = get_pcap_timestamp_types(pch, NULL);
        pcap_close(pch);

        /*
         * This doesn't return warnings for remote devices, and
         * we don't use it for local devices.
         */
        *status = CAP_DEVICE_OPEN_NO_ERR;
        *status_str = NULL;
        return caps;
    }
#endif /* defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE) */

    /*
     * Local interface.
     */
    return get_if_capabilities_local(interface_opts, status, status_str);
}

pcap_t *
open_capture_device(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
	struct pcap_rmtauth auth;
#endif

	/* Open the network interface to capture from it.
	   Some versions of libpcap may put warnings into the error buffer
	   if they succeed; to tell if that's happened, we have to clear
	   the error buffer, and check if it's still a null string.  */
	ws_debug("Entering open_capture_device().");
	*open_status = CAP_DEVICE_OPEN_NO_ERR;
	(*open_status_str)[0] = '\0';
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
		ws_debug("Calling pcap_open() using name %s, snaplen %d, promisc_mode %d, datatx_udp %d, nocap_rpcap %d.",
		    interface_opts->name, snaplen,
		    interface_opts->promisc_mode, interface_opts->datatx_udp,
		    interface_opts->nocap_rpcap);
		pcap_h = pcap_open(interface_opts->name, snaplen,
		    /* flags */
		    (interface_opts->promisc_mode ? PCAP_OPENFLAG_PROMISCUOUS : 0) |
		    (interface_opts->datatx_udp ? PCAP_OPENFLAG_DATATX_UDP : 0) |
		    (interface_opts->nocap_rpcap ? PCAP_OPENFLAG_NOCAPTURE_RPCAP : 0),
		    timeout, &auth, *open_status_str);
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
			*open_status = CAP_DEVICE_OPEN_ERROR_GENERIC;
			if (strcmp(*open_status_str, "not supported") == 0) {
				/*
				 * macOS 14's pcap_open(), which is a stub
				 * that always returns NULL with an error
				 * message of "not supported".
				 *
				 * In this case, as we passed it an rpcap://
				 * URL, treat that as meaning "remote capture
				 * not supported".
				 */
				(void) g_strlcpy(*open_status_str,
				    "Remote capture not supported",
				    PCAP_ERRBUF_SIZE);
			}

			/* Did pcap actually supply an error message? */
			if ((*open_status_str)[0] == '\0') {
				/*
				 * Work around known WinPcap bug wherein
				 * no error message is filled in on a
				 * failure to open an rpcap: URL.
				 */
				(void) g_strlcpy(*open_status_str,
				    "Unknown error (pcap bug; actual error cause not reported)",
				    sizeof *open_status_str);
			}
		}
		ws_debug("pcap_open() returned %p.", (void *)pcap_h);
		ws_debug("open_capture_device %s : %s", pcap_h ? "SUCCESS" : "FAILURE", interface_opts->name);
		/*
		 * This doesn't return warnings for remote devices, and
		 * we don't use it for local devices.
		 */
		*open_status = CAP_DEVICE_OPEN_NO_ERR;
		return pcap_h;
	}
#endif

	pcap_h = open_capture_device_local(capture_opts, interface_opts,
	    timeout, open_status, open_status_str);
	ws_debug("open_capture_device %s : %s", pcap_h ? "SUCCESS" : "FAILURE", interface_opts->name);
	return pcap_h;
}

/*
 * Platform-dependent suggestions for fixing permissions.
 */

#ifdef HAVE_LIBCAP
  #define LIBCAP_PERMISSIONS_SUGGESTION \
    "\n\n" \
    "If you did not install Wireshark from a package, ensure that Dumpcap " \
    "has the needed CAP_NET_RAW and CAP_NET_ADMIN capabilities by running " \
    "\n\n" \
    "    sudo setcap cap_net_raw,cap_net_admin=ep {path/to/}dumpcap" \
    "\n\n" \
    "and then restarting Wireshark."
#else
  #define LIBCAP_PERMISSIONS_SUGGESTION
#endif

#if defined(__linux__)
  #define PLATFORM_PERMISSIONS_SUGGESTION \
    "\n\n" \
    "On Debian and Debian derivatives such as Ubuntu, if you have " \
    "installed Wireshark from a package, try running" \
    "\n\n" \
    "    sudo dpkg-reconfigure wireshark-common" \
    "\n\n" \
    "selecting \"<Yes>\" in response to the question" \
    "\n\n" \
    "    Should non-superusers be able to capture packets?" \
    "\n\n" \
    "adding yourself to the \"wireshark\" group by running" \
    "\n\n" \
    "    sudo usermod -a -G wireshark {your username}" \
    "\n\n" \
    "and then logging out and logging back in again." \
    LIBCAP_PERMISSIONS_SUGGESTION
#elif defined(__APPLE__)
  #define PLATFORM_PERMISSIONS_SUGGESTION \
    "\n\n" \
    "If you installed Wireshark using the package from wireshark.org, " \
    "close this dialog and click on the \"installing ChmodBPF\" link in " \
    "\"You can fix this by installing ChmodBPF.\" on the main screen, " \
    "and then complete the installation procedure."
#else
  #define PLATFORM_PERMISSIONS_SUGGESTION
#endif

#if defined(_WIN32)
static const char *
get_platform_pcap_failure_secondary_error_message(const char *open_status_str)
{
    /*
     * The error string begins with the error produced by WinPcap
     * and Npcap if attempting to set promiscuous mode fails.
     * (Note that this string could have a specific error message
     * from an NDIS error after the initial part, so we do a prefix
     * check rather than an exact match check.)
     *
     * If this is with Npcap 1.71 through 1.73, which have bugs that
     * cause this error on Windows 11 with some drivers, suggest that
     * the user upgrade to the current version of Npcap;
     * otherwise, suggest that they turn off promiscuous mode
     * on that device.
     */
    static const char promisc_failed[] =
        "failed to set hardware filter to promiscuous mode";

    if (strncmp(open_status_str, promisc_failed, sizeof promisc_failed - 1) == 0) {
        unsigned int npcap_major, npcap_minor;

        if (caplibs_get_npcap_version(&npcap_major, &npcap_minor)) {
            if (npcap_major == 1 &&
                (npcap_minor >= 71 && npcap_minor <= 73)) {
                return
"This is a bug in your version of Npcap.\n"
"\n"
"If you need to use promiscuous mode, you must upgrade to the current "
"version of Npcap, which is available from https://npcap.com/\n"
"\n"
"Otherwise, turn off promiscuous mode for this device.";
            }
        }
        return
              "Please turn off promiscuous mode for this device.";
    }
    return NULL;
}
#elif defined(__linux__)
static const char *
get_platform_pcap_failure_secondary_error_message(const char *open_status_str)
{
    /*
     * The error string is the message provided by libpcap on
     * Linux if an attempt to open a PF_PACKET socket failed
     * with EAFNOSUPPORT.  This probably means that either 1)
     * the kernel doesn't have PF_PACKET support configured in
     * or 2) this is a Flatpak version of Wireshark that's been
     * sandboxed in a way that disallows opening PF_PACKET
     * sockets.
     *
     * Suggest that the user find some other package of
     * Wireshark if they want to capture traffic and are
     * running a Flatpak of Wireshark or that they configure
     * PF_PACKET support back in if it's configured out.
     */
    static const char af_notsup[] =
        "socket: Address family not supported by protocol";

    if (strcmp(open_status_str, af_notsup) == 0) {
        return
                   "If you are running Wireshark from a Flatpak package, "
                   "it does not support packet capture; you will need "
                   "to run a different version of Wireshark in order "
                   "to capture traffic.\n"
                   "\n"
                   "Otherwise, if your machine is running a kernel that "
                   "was not configured with CONFIG_PACKET, that kernel "
                   "does not support packet capture; you will need to "
                   "use a kernel configured with CONFIG_PACKET.";
    }
    return NULL;
}
#else
static const char *
get_platform_pcap_failure_secondary_error_message(const char *open_status_str _U_)
{
    /* No such message for platforms not handled above. */
    return NULL;
}
#endif

const char *
get_pcap_failure_secondary_error_message(cap_device_open_status open_status,
                                         const char *open_status_str)
{
    const char *platform_secondary_error_message;

#ifdef _WIN32
    /*
     * On Windows, first make sure they *have* Npcap installed.
     */
    if (!has_npcap) {
        return
            "In order to capture packets, Npcap must be installed. See\n"
            "\n"
            "        https://npcap.com/\n"
            "\n"
            "for a downloadable version of Npcap and for instructions on how to\n"
            "install it.";
    }
#endif

    /*
     * OK, now just return a largely platform-independent error that might
     * have platform-specific suggestions at the end (for example, suggestions
     * for how to get permission to capture).
     */
    switch (open_status) {

    case CAP_DEVICE_OPEN_NO_ERR:
    case CAP_DEVICE_OPEN_WARNING_PROMISC_NOTSUP:
    case CAP_DEVICE_OPEN_WARNING_TSTAMP_TYPE_NOTSUP:
    case CAP_DEVICE_OPEN_WARNING_OTHER:
        /* This should not happen, as those aren't errors. */
        return "";

    case CAP_DEVICE_OPEN_ERROR_NO_SUCH_DEVICE:
    case CAP_DEVICE_OPEN_ERROR_RFMON_NOTSUP:
    case CAP_DEVICE_OPEN_ERROR_IFACE_NOT_UP:
        /*
         * Not clear what suggestions to make for these cases.
         */
        return "";

    case CAP_DEVICE_OPEN_ERROR_PERM_DENIED:
    case CAP_DEVICE_OPEN_ERROR_PROMISC_PERM_DENIED:
        /*
         * This is a permissions error, so no need to specify any other
         * warnings.
         */
        return
               "Please check to make sure you have sufficient permissions."
               PLATFORM_PERMISSIONS_SUGGESTION;
        break;

    case CAP_DEVICE_OPEN_ERROR_OTHER:
    case CAP_DEVICE_OPEN_ERROR_GENERIC:
        /*
         * We don't know what kind of error it is.  See if there's a hint
         * in the error string; if not, throw all generic suggestions at
         * the user.
         *
         * First, check for some text that pops up in some errors.
         * Do platform-specific checks first.
         */
        platform_secondary_error_message =
            get_platform_pcap_failure_secondary_error_message(open_status_str);
        if (platform_secondary_error_message != NULL) {
            /* We got one, so return it. */
            return platform_secondary_error_message;
        }

        /*
         * Not one of those particular problems.  Was this a "generic"
         * error from pcap_open_live() or pcap_open(), in which case
         * it might be a permissions error?
         */
        if (open_status == CAP_DEVICE_OPEN_ERROR_GENERIC) {
            /* Yes. */
            return
                   "Please check to make sure you have sufficient permissions, and that you have "
                   "the proper interface or pipe specified."
                   PLATFORM_PERMISSIONS_SUGGESTION;
        } else {
            /*
             * This is not a permissions error, so no need to suggest
             * checking permissions.
             */
            return
                "Please check that you have the proper interface or pipe specified.";
        }
        break;

    default:
        /*
         * This is not a permissions error, so no need to suggest
         * checking permissions.
         */
        return
            "Please check that you have the proper interface or pipe specified.";
        break;
    }
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
