/** @file
 *
 * Routines supporting the use of Windows friendly interface names within Wireshark
 * Copyright 2011-2012, Mike Garratt <wireshark@evn.co.nz>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_WIN_IFNAMES_H
#define CAPTURE_WIN_IFNAMES_H

/**
 * @brief Get the friendly name for a network interface using its GUID.
 *
 * If a string is a GUID in {}, fill in a GUID structure with the GUID
 * value and return true; otherwise, if the string is not a valid GUID
 * in {}, return false.
 *
 * @param guid Pointer to the GUID structure representing the network interface.
 * @return A dynamically allocated string containing the friendly name of the interface, or NULL if the operation fails.
 */
extern bool parse_as_guid(const char *guid_text, GUID *guid);

/* Get the friendly name for the given GUID */

/**
 * @brief Get the friendly name for a network interface using its GUID.
 *
 * @param guid Pointer to the GUID structure representing the network interface.
 * @return A dynamically allocated string containing the friendly name of the interface, or NULL if the operation fails.
 */
extern char *get_interface_friendly_name_from_device_guid(__in GUID *guid);

/**
 * @brief Get the friendly name for a network interface using its device name.
 *
 * Given a device name, try to extract the GUID from it and parse it.
 * If that fails, return NULL; if that succeeds, attempt to get the
 * friendly name for the interface in question.  If that fails, return
 * NULL, otherwise return the friendly name, allocated with g_malloc()
 * (so that it must be freed with g_free()).
 *
 * @param interface_devicename Pointer to the string representing the network interface's device name.
 * @return A dynamically allocated string containing the friendly name of the interface, or NULL if the operation fails.
 */
extern char *get_windows_interface_friendly_name(const char *interface_devicename);

#endif
