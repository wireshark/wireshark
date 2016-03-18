/* dissector_filters.h
 * Routines for dissector-generated conversation filters for use as
 * display and color filters
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

#ifndef __DISSECTOR_FILTERS_H__
#define __DISSECTOR_FILTERS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 */

/** callback function definition: is a filter available for this packet? */
typedef gboolean (*is_filter_valid_func)(struct _packet_info *pinfo);

/** callback function definition: return the available filter for this packet or NULL if no filter is available,
    Filter needs to be freed after use */
typedef gchar* (*build_filter_string_func)(struct _packet_info *pinfo);

/** register a dissector filter */
WS_DLL_PUBLIC void register_conversation_filter(const char *proto_name, const char *display_name,
                                                      is_filter_valid_func is_filter_valid, build_filter_string_func build_filter_string);

WS_DLL_PUBLIC struct conversation_filter_s* find_conversation_filter(const char *proto_name);

/*** THE FOLLOWING SHOULD NOT BE USED BY ANY DISSECTORS!!! ***/

typedef struct conversation_filter_s {
    const char *              proto_name;
    const char *              display_name;
    is_filter_valid_func      is_filter_valid;
    build_filter_string_func  build_filter_string;
} conversation_filter_t;

WS_DLL_PUBLIC GList *conv_filter_list;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* dissector_filters.h */
