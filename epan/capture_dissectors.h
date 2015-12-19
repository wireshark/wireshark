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
#include <capture_info.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 */

/** callback function definition for capture dissectors */
typedef gboolean (*capture_dissector_t)(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

/* a protocol uses the function to register a capture sub-dissector table
 */
WS_DLL_PUBLIC void register_capture_dissector_table(const char *name, const char *ui_name);


/** Register a new capture dissector. */
WS_DLL_PUBLIC void register_capture_dissector(const char* name, const guint32 pattern, capture_dissector_t dissector, const int proto);

WS_DLL_PUBLIC gboolean try_capture_dissector(const char* name, const guint32 pattern, const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

WS_DLL_PUBLIC guint32 capture_dissector_get_count(packet_counts* counts, const int proto);
WS_DLL_PUBLIC void capture_dissector_increment_count(capture_packet_info_t *cpinfo, const int proto);

extern void capture_dissector_init(void);
extern void capture_dissector_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture_dissectors.h */
