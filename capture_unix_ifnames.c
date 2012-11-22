/* capture_unix_ifnames.c
 * Routines supporting the use of UN*X friendly interface names, if any,
 * within Wireshark
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#include <glib.h>

#include "capture_unix_ifnames.h"

/*
 * Given an interface name, find the "friendly name" for the interface.
 */

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include "cfutils.h"

/*
 * On OS X, we do that by getting all the interfaces that the System
 * Configuration framework knows about, look for the one with a "BSD
 * name" matching the interface name, and, if we find it, return its
 * "localized display name", if it has one.
 */
char *
get_unix_interface_friendly_name(const char *ifname)
{
	CFStringRef ifname_CFString;
	CFArrayRef interfaces;
	CFIndex num_interfaces;
	CFIndex i;
	SCNetworkInterfaceRef interface;
	CFStringRef bsdname_CFString;
	CFStringRef friendly_name_CFString;
	char *friendly_name = NULL;

	interfaces = SCNetworkInterfaceCopyAll();
	if (interfaces == NULL) {
		/*
		 * Couldn't get a list of interfaces.
		 */
		return NULL;
	}

	ifname_CFString = CFStringCreateWithCString(kCFAllocatorDefault,
	    ifname, kCFStringEncodingUTF8);
	if (ifname_CFString == NULL) {
		/*
		 * Couldn't convert the interface name to a CFString.
		 */
		CFRelease(interfaces);
		return NULL;
	}

	num_interfaces = CFArrayGetCount(interfaces);
	for (i = 0; i < num_interfaces; i++) {
		interface = CFArrayGetValueAtIndex(interfaces, i);
		bsdname_CFString = SCNetworkInterfaceGetBSDName(interface);
		if (bsdname_CFString == NULL) {
			/*
			 * This interface has no BSD name, so it's not
			 * a regular network interface.
			 */
			continue;
		}
		if (CFStringCompare(ifname_CFString, bsdname_CFString, 0) == 0) {
			/*
			 * This is the interface.
			 */
			friendly_name_CFString = SCNetworkInterfaceGetLocalizedDisplayName(interface);
			if (friendly_name_CFString != NULL)
				friendly_name = CFString_to_C_string(friendly_name_CFString);
			break;
		}
	}

	CFRelease(interfaces);
	return friendly_name;
}

#else /* __APPLE__ */

/*
 * Nothing supported on other platforms.
 */
char *
get_unix_interface_friendly_name(const char *ifname _U_)
{
	return NULL;
}

#endif /* __APPLE__ */
