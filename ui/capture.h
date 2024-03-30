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

#include "capture_opts.h"
#include "capture_info.h"
#include "cfile.h"
#include "capture/capture_session.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    capture_cb_capture_prepared,
    capture_cb_capture_update_started,
    capture_cb_capture_update_continue,
    capture_cb_capture_update_finished,
    capture_cb_capture_fixed_started,
    capture_cb_capture_fixed_continue,
    capture_cb_capture_fixed_finished,
    capture_cb_capture_stopping,
    capture_cb_capture_failed
} capture_cbs;

typedef void (*capture_callback_t) (int event, capture_session *cap_session,
                                    void *user_data);

extern void
capture_callback_add(capture_callback_t func, void *user_data);

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

/** Stop a capture session (usually from a menu item). */
extern void
capture_stop(capture_session *cap_session);

/** Terminate the capture child cleanly when exiting. */
extern void
capture_kill_child(capture_session *cap_session);

struct if_stat_cache_s;
typedef struct if_stat_cache_s if_stat_cache_t;

/**
 * Start gathering capture statistics for the interfaces specified.
 * @param capture_opts A structure containing options for the capture.
 * @return A pointer to the statistics state data.
 */
extern WS_RETNONNULL if_stat_cache_t * capture_stat_start(capture_options *capture_opts);

/**
 * Retrieve the list of interfaces and their capabilities, and start
 * gathering capture statistics for the interfaces.
 * @param capture_opts A structure containing options for the capture.
 * @param[out] if_list A pointer that will store a GList of if_info_t.
 * @return A pointer to the statistics state data.
 */
extern WS_RETNONNULL if_stat_cache_t * capture_interface_stat_start(capture_options *capture_opts, GList **if_list);

/**
 * Fetch capture statistics, similar to pcap_stats().
 */
struct pcap_stat; /* Stub in case we don't or haven't yet included pcap.h */
extern bool capture_stats(if_stat_cache_t *sc, char *ifname, struct pcap_stat *ps);

/**
 * Stop gathering capture statistics.
 */
void capture_stat_stop(if_stat_cache_t *sc);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture.h */
