/* capture_win_ifnames.h
 * Routines supporting the use of Windows friendly interface names within Wireshark
 * Copyright 2011-2012, Mike Garratt <wireshark@evn.co.nz>
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

#ifndef CAPTURE_WIN_IFNAMES_H
#define CAPTURE_WIN_IFNAMES_H

/*
 * If a string is a GUID in {}, fill in a GUID structure with the GUID
 * value and return TRUE; otherwise, if the string is not a valid GUID
 * in {}, return FALSE.
 */
extern gboolean parse_as_guid(const char *guid_text, GUID *guid);

/* Get the friendly name for the given GUID */
extern char *get_interface_friendly_name_from_device_guid(GUID *guid);

/*
 * Given an interface name, try to extract the GUID from it and parse it.
 * If that fails, return NULL; if that succeeds, attempt to get the
 * friendly name for the interface in question.  If that fails, return
 * NULL, otherwise return the friendly name, allocated with g_malloc()
 * (so that it must be freed with g_free()).
 */
extern char *get_windows_interface_friendly_name(const char *interface_devicename);

#endif
