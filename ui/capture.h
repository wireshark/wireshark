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

/*
 * Interface statistics (dumpcap -S) are now collected off-thread by the Qt
 * InterfaceStatsWorker, which talks to sync_interface_stats_open() directly.
 * The former C if_stat_cache API lived here and is gone.
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* capture.h */
