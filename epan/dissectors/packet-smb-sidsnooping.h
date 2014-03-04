/* packet-smb-sidsnooping.h
 * Routines for snooping SID to name mappings
 * Copyright 2003, Ronnie Sahlberg
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

#ifndef _PACKET_SMB_SID_SNOOPING_H_
#define _PACKET_SMB_SID_SNOOPING_H_

#include "ws_symbol_export.h"

/* With MSVC and a libwireshark.dll, we need a
 * special declaration for sid_name_table.
 */
WS_DLL_PUBLIC GHashTable *sid_name_table;

typedef struct _sid_name {
	char *sid;
	char *name;
} sid_name;

WS_DLL_PUBLIC
char *find_sid_name(const char *sid);

#endif
