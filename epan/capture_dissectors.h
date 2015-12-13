/* capture_dissectors.h
 * Routines for handling capture dissectors
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

#ifndef __CAPTURE_DISSECTORS_H__
#define __CAPTURE_DISSECTORS_H__

#include "ws_symbol_export.h"
#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 */

/** callback function definition: is a filter available for this packet? */
typedef void (*capture_dissector_t)(const guchar *pd, int offset, int len, packet_counts *ld, const union wtap_pseudo_header *pseudo_header);


/** Register a new capture dissector. */
WS_DLL_PUBLIC void register_capture_dissector(gint linktype, capture_dissector_t dissector, const int proto);

WS_DLL_PUBLIC void call_capture_dissector(gint linktype, const guchar *pd, int offset, int len, packet_counts *ld, const union wtap_pseudo_header *pseudo_header);

extern void capture_dissector_init(void);
extern void capture_dissector_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture_dissectors.h */
