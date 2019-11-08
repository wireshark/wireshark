/* conversation_filter.h
 * Routines for dissector-generated conversation filters for use as
 * display and color filters
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

/* Cleanup internal structures */
extern void conversation_filters_cleanup(void);

/**
 * Tries to build a suitable display filter for the conversation in the current
 * packet. More specific matches are tried first (like TCP ports) followed by
 * less specific ones (IP addresses). NULL is returned when no filter is found.
 *
 * The returned filter should be freed with g_free.
 */
WS_DLL_PUBLIC gchar *conversation_filter_from_packet(struct _packet_info *pinfo);

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

#endif /* conversation_filter.h */
