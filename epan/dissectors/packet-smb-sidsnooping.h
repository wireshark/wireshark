/* packet-smb-sidsnooping.h
 * Routines for snooping SID to name mappings
 * Copyright 2003, Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_SMB_SID_SNOOPING_H_
#define _PACKET_SMB_SID_SNOOPING_H_

#include "ws_symbol_export.h"

/* With MSVC and a libwireshark.dll, we need a
 * special declaration for sid_name_table.
 */
WS_DLL_PUBLIC GHashTable *sid_name_table;

WS_DLL_PUBLIC
const char *find_sid_name(const char *sid);

#endif
