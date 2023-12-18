/* capture_sync.h
 * Synchronisation between Wireshark capture parent and child instances
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/** @file
 *
 *  Sync mode capture (internal interface).
 *
 *  Will start a new Wireshark child instance which will do the actual capture
 *  work.
 */

#ifndef __CAPTURE_SYNC_H__
#define __CAPTURE_SYNC_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _info_data;

/**
 * Start a new capture session.
 *  Create a capture child which is doing the real capture work.
 *  The various capture_input_... functions will be called, if something had
 *  happened.
 *
 *  Most of the parameters are passed through the global capture_opts.
 *
 *  @param capture_opts the options
 *  @param capture_comments if not NULL, a GPtrArray * to a set of comments
 *   to put in the capture file's Section Header Block if it's a pcapng file
 *  @param cap_session a handle for the capture session
 *  @param cap_data a struct with capture info data
 *  @param update_cb update screen
 *  @return             true if a capture could be started, false if not
 */
extern bool
sync_pipe_start(capture_options *capture_opts, GPtrArray *capture_comments,
                capture_session *cap_session, struct _info_data* cap_data,
                void(*update_cb)(void));

/** User wants to stop capturing, gracefully close the capture child */
extern void
sync_pipe_stop(capture_session *cap_session);

/** User wants to stop the program, just kill the child as soon as possible */
extern void
sync_pipe_kill(ws_process_id fork_child);

/**
 * Set wireless channel using dumpcap
 *  On success, *data points to a buffer containing the dumpcap output,
 *  *primary_msg and *secondary_msg are NULL, and 0 is returned.  *data
 *  must be freed with g_free().
 *
 *  On failure, *data is NULL, *primary_msg points to an error message,
 *  *secondary_msg either points to an additional error message or is
 *  NULL, and -1 or errno value is returned; *primary_msg, and
 *  *secondary_msg if not NULL must be freed with g_free().
 *
 *  @param iface (monitor) network interface name
 *  @param freq channel control frequency string (in MHz)
 *  @param type channel type string (or NULL if not used)
 *  @param center_freq1 VHT channel center frequency (or NULL if not used)
 *  @param center_freq2 VHT channel center frequency 2 (or NULL if not used)
 *  @param data On success, *data points to a buffer containing the dumpcap output, On failure *data is NULL
 *  @param primary_msg On success NULL, On failure points to an error message
 *  @param secondary_msg On success NULL, On failure either points to an additional error message or is NULL
 *  @param update_cb update callback
 *  @return 0 on success
 */
extern int
sync_interface_set_80211_chan(const char *iface, const char *freq, const char *type,
                              const char *center_freq1, const char *center_freq2,
                              char **data, char **primary_msg,
                              char **secondary_msg, void (*update_cb)(void));

/** Get an interface list using dumpcap */
extern int
sync_interface_list_open(char **data, char **primary_msg,
                         char **secondary_msg, void (*update_cb)(void));

/** Get interface capabilities using dumpcap */
extern int
sync_if_capabilities_open(const char *ifname, bool monitor_mode, const char* auth,
                          char **data, char **primary_msg,
                          char **secondary_msg, void (*update_cb)(void));

extern int
sync_if_list_capabilities_open(GList *ifqueries,
                          char **data, char **primary_msg,
                          char **secondary_msg, void (*update_cb)(void));

/** Start getting interface statistics using dumpcap. */
extern int
sync_interface_stats_open(int *read_fd, ws_process_id *fork_child, char **data, char **msg, void (*update_cb)(void));

/** Stop gathering statistics. */
extern int
sync_interface_stats_close(int *read_fd, ws_process_id *fork_child, char **msg);

/** Read a line from a pipe, similar to fgets.  Non-blocking. */
extern int
sync_pipe_gets_nonblock(int pipe_fd, char *bytes, int max);

/* set a callback to be called after fork with the pid of the forked child */
extern void capture_sync_set_fetch_dumpcap_pid_cb(void(*cb)(ws_process_id pid));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_SYNC_H__ */
