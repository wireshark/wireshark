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

#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 */

/** Initialize internal structures */
extern void conversation_filters_init(void);

/**
 * Callback function which checks for filter availability.
 *
 * @param pinfo packet_info pointer for the current packet.
 * @param user_data User data provided to register_conversation_filter or register_log_conversation_filter.
 * @return true if the packet has a valid conversation filter, false otherwise.
 */
typedef bool (*is_filter_valid_func)(struct _packet_info *pinfo, void *user_data);

/** callback function definition: return the available filter for this packet or NULL if no filter is available,
    Filter needs to be freed after use */
/**
 * Callback function which creates a conversation filter.
 *
 * @param pinfo packet_info pointer for the current packet.
 * @param user_data User data provided to register_conversation_filter or register_log_conversation_filter.
 * @return A filter for the conversation on success, NULL on failure. The filter must be gfreed.
 */
typedef char* (*build_filter_string_func)(struct _packet_info *pinfo, void *user_data);

/**
 * Register a new packet conversation filter.
 *
 * @param proto_name The protocol name.
 * @param display_name A friendly name for the filter.
 * @param is_filter_valid A callback function conforming to is_filter_valid_func.
 * @param build_filter_string A callback function conforming to build_filter_string_func.
 * @param user_data User-defined data which is passed to the callback functions. Can be NULL.
 */
WS_DLL_PUBLIC void register_conversation_filter(const char *proto_name, const char *display_name,
                                                      is_filter_valid_func is_filter_valid, build_filter_string_func build_filter_string, void *user_data);

/**
 * Register a new log conversation filter.
 *
 * @param proto_name The protocol name.
 * @param display_name A friendly name for the filter.
 * @param is_filter_valid A callback function conforming to is_filter_valid_func.
 * @param build_filter_string A callback function conforming to build_filter_string_func.
 * @param user_data User-defined data which is passed to the callback functions. Can be NULL.
 */
WS_DLL_PUBLIC void register_log_conversation_filter(const char *proto_name, const char *display_name,
                                                      is_filter_valid_func is_filter_valid, build_filter_string_func build_filter_string, void *user_data);
/**
 * Prepend a protocol to the list of filterable protocols.
 * @param proto_name A valid protocol name.
 */
WS_DLL_PUBLIC void add_conversation_filter_protocol(const char *proto_name);

/** Cleanup internal structures */
extern void conversation_filters_cleanup(void);

/**
 * Tries to build a suitable display filter for the conversation in the current
 * packet. More specific matches are tried first (like TCP ports) followed by
 * less specific ones (IP addresses). NULL is returned when no filter is found.
 *
 * @param pinfo Packet info
 * @return A display filter for the conversation. Should be freed with g_free.
 */
WS_DLL_PUBLIC char *conversation_filter_from_packet(struct _packet_info *pinfo);

/**
 * Tries to build a suitable display filter for the conversation in the current
 * log entry. More specific matches are tried first (like TCP ports) followed by
 * less specific ones (IP addresses). NULL is returned when no filter is found.
 *
 * @param pinfo Packet info
 * @return A display filter for the conversation. Should be freed with g_free.
 */
WS_DLL_PUBLIC char *conversation_filter_from_log(struct _packet_info *pinfo);

/*** THE FOLLOWING SHOULD NOT BE USED BY ANY DISSECTORS!!! ***/

typedef struct conversation_filter_s {
    const char *              proto_name;
    const char *              display_name;
    is_filter_valid_func      is_filter_valid;
    build_filter_string_func  build_filter_string;
    void *                    user_data;
} conversation_filter_t;

WS_DLL_PUBLIC GList *packet_conv_filter_list;
WS_DLL_PUBLIC GList *log_conv_filter_list;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* conversation_filter.h */
