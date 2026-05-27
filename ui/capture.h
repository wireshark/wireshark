/** @file
 *
 * Definitions for packet capture windows
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This file should only be included if libpcap is present */

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

/** @file
 *  Capture related things.
 */

#include "ui/capture_opts.h"
#include "capture_info.h"
#include <epan/cfile.h>
#include "capture/capture_session.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Event identifiers for live capture lifecycle callbacks.
 */
typedef enum {
    capture_cb_capture_prepared,        /**< Capture interfaces have been opened and the capture is ready to start */
    capture_cb_capture_update_started,  /**< An updatable (real-time) capture session has started */
    capture_cb_capture_update_continue, /**< An updatable capture session has received new packets and the display should refresh */
    capture_cb_capture_update_finished, /**< An updatable capture session has ended normally */
    capture_cb_capture_fixed_started,   /**< A fixed (non-updating) capture session has started */
    capture_cb_capture_fixed_continue,  /**< A fixed capture session is continuing; progress update without display refresh */
    capture_cb_capture_fixed_finished,  /**< A fixed capture session has ended normally */
    capture_cb_capture_stopping,        /**< The capture is in the process of stopping (user-initiated or limit reached) */
    capture_cb_capture_failed           /**< The capture session failed to start or was terminated due to an error */
} capture_cbs;

typedef void (*capture_callback_t) (int event, capture_session *cap_session,
                                    void *user_data);

/**
 * @brief Add a capture callback.
 * @param func The callback function.
 * @param user_data User data to pass to the callback.
 */
extern void
capture_callback_add(capture_callback_t func, void *user_data);

/**
 * @brief Remove a capture callback.
 * @param func The callback function.
 * @param user_data User data to pass to the callback.
 */
extern void
capture_callback_remove(capture_callback_t func, void *user_data);

/**
 * Initialize a capture session.
 *
 * @param cap_session the handle for the capture session
 * @param cf the capture_file for the file
 */
extern void
capture_input_init(capture_session *cap_session, capture_file *cf);

/**
 * Start a capture session.
 *
 * @param capture_opts the numerous capture options
 * @param capture_comments if not NULL, a GPtrArray * to a set of comments
 *  to put in the capture file's Section Header Block if it's a pcapng file
 * @param cap_session the handle for the capture session
 * @param cap_data a struct with capture info data
 * @param update_cb update screen
 * @return true if the capture starts successfully, false otherwise.
 */
extern bool
capture_start(capture_options *capture_opts, GPtrArray *capture_comments,
              capture_session *cap_session, info_data_t* cap_data,
              void(*update_cb)(void));

/**
 * @brief Stop a capture session (usually from a menu item).
 * @param cap_session The handle for the capture session.
 */
extern void
capture_stop(capture_session *cap_session);

/**
 * @brief Terminate the capture child cleanly when exiting.
 * @param cap_session The handle for the capture session.
 */
extern void
capture_kill_child(capture_session *cap_session);

struct if_stat_cache_s;
typedef struct if_stat_cache_s if_stat_cache_t;

/**
 * @brief Start gathering capture statistics for the interfaces specified.
 *
 * @param capture_opts A structure containing options for the capture.
 * @return A pointer to the statistics state data.
 */
extern WS_RETNONNULL if_stat_cache_t * capture_stat_start(capture_options *capture_opts);

/**
 * @brief Retrieve the list of interfaces and their capabilities, and start
 * gathering capture statistics for the interfaces.
 *
 * @param capture_opts A structure containing options for the capture.
 * @param[out] if_list A pointer that will store a GList of if_info_t.
 * @return A pointer to the statistics state data.
 */
extern WS_RETNONNULL if_stat_cache_t * capture_interface_stat_start(capture_options *capture_opts, GList **if_list);

/**
 * Fetch capture statistics, similar to pcap_stats().
 */
struct pcap_stat; /* Stub in case we don't or haven't yet included pcap.h */

/**
 * @brief Fetch capture statistics for the interfaces specified.
 * @param sc A pointer to the statistics state data.
 * @param ifname The name of the interface to fetch statistics for.
 * @param ps A pointer to a pcap_stat structure to fill in with the statistics.
 * @return true if the statistics were successfully fetched, false otherwise.
 */
extern bool capture_stats(if_stat_cache_t *sc, char *ifname, struct pcap_stat *ps);

/**
 * @brief Stop gathering capture statistics.
 * @param sc A pointer to the statistics state data.
 */
void capture_stat_stop(if_stat_cache_t *sc);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture.h */
