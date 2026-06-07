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

#include <wsutil/processes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _info_data;

typedef struct _capture_session capture_session;
typedef struct capture_options_tag capture_options;

/**
 * @brief Start a new capture session.
 *
 * Create a capture child which is doing the real capture work.
 * The various capture_input_... functions will be called, if something had
 * happened.
 *
 * Most of the parameters are passed through the global capture_opts.
 *
 * @param capture_opts the options
 * @param capture_comments if not NULL, a GPtrArray * to a set of comments
 *  to put in the capture file's Section Header Block if it's a pcapng file
 * @param cap_session a handle for the capture session
 * @param cap_data a struct with capture info data
 * @param update_cb update screen
 * @return true if a capture could be started, false if not
 */
extern bool
sync_pipe_start(capture_options *capture_opts, GPtrArray *capture_comments,
                capture_session *cap_session, struct _info_data* cap_data,
                void(*update_cb)(void));

/**
 * @brief Request that the capture child stop capturing and shut down cleanly.
 *
 * When the user wants to stop capturing, gracefully close the capture child
 *
 * @param cap_session  The active capture session to be stopped.
 */
extern void
sync_pipe_stop(capture_session *cap_session);

/**
 * @brief Forcefully terminate the capture child process as quickly as possible.
 *
 * When the user wants to stop the program, just kill the child as soon as possible
 *
 * @param fork_child The process ID of the capture child to kill.
 */
extern void
sync_pipe_kill(ws_process_id fork_child);

/**
 * @brief Set wireless channel using dumpcap
 *
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

/**
 * @brief Compile a capture filter and get its BPF bytecode (in human-readable form.)
 *
 * This is necessary on Linux because, as pcap_compile(3PCAP) says:
 * "On Linux, if the pcap_t handle corresponds to a live packet capture, the
 * resulting filter program may use Linux BPF extensions;" this will produce
 * the actual filter used for a live capture as opposed to the compiled version
 * without extensions that pcap_open_dead(3PCAP) produces. (However, it requires
 * permissions to open the device.)
 *
 *  @param ifname network interface name
 *  @param filter capture filter string
 *  @param linktype link layer type (-1 to use device default)
 *  @param optimize whether to optimize the filter
 *  @param data On success, *data points to a buffer containing the dumpcap output, On failure *data is NULL
 *  @param primary_msg On success NULL, On failure points to an error message
 *  @param secondary_msg On success NULL, On failure either points to an additional error message or is NULL
 *  @param update_cb update callback
 */
extern int
sync_if_bpf_filter_open(const char *ifname, const char* filter, int linktype,
                        bool optimize, char **data, char **primary_msg,
                        char **secondary_msg, void (*update_cb)(void));

/**
 * @brief Get an interface list using dumpcap.
 *
 * @param data            On success, set to dumpcap output; on failure, set to NULL.
 * @param primary_msg     On success NULL; on failure, set to an error message.
 * @param secondary_msg   On success NULL; on failure, set to an additional error message or NULL.
 * @param update_cb       Callback invoked to update status.
 *
 * @return 0 on success, or -1/errno on failure.
 */
extern int
sync_interface_list_open(char **data, char **primary_msg,
                         char **secondary_msg, void (*update_cb)(void));

/**
 * @brief Get interface capabilities using dumpcap.
 *
 * @param ifname          Interface name for which capabilities are requested.
 * @param monitor_mode    Whether to query capabilities in monitor mode.
 * @param auth            Authentication string, or NULL if unused.
 * @param data            On success, set to dumpcap output; on failure, set to NULL.
 * @param primary_msg     On success NULL; on failure, set to an error message.
 * @param secondary_msg   On success NULL; on failure, set to an additional error message or NULL.
 * @param update_cb       Callback invoked to update status.
 *
 * @return 0 on success, or -1/errno on failure.
 */
extern int
sync_if_capabilities_open(const char *ifname, bool monitor_mode, const char* auth,
                          char **data, char **primary_msg,
                          char **secondary_msg, void (*update_cb)(void));

/**
 * @brief Start getting interface statistics using dumpcap.
 *
 * @param ifqueries List of interface queries.
 * @param data Pointer to store additional data.
 * @param primary_msg Pointer to store primary message.
 * @param secondary_msg Pointer to store secondary message.
 * @param update_cb Callback function for updates.
 * @return Result code (-1 on error, otherwise on success).
 */
extern int
sync_if_list_capabilities_open(GList *ifqueries,
                          char **data, char **primary_msg,
                          char **secondary_msg, void (*update_cb)(void));

/**
 * @brief Open an interface statistics stream using dumpcap.
 *
 * @param read_fd     On success, set to a file descriptor for reading stats.
 * @param fork_child  On success, set to the PID of the dumpcap child process.
 * @param data        On success, initial dumpcap output; on failure, NULL.
 * @param msg         On success NULL; on failure, an error message.
 * @param update_cb   Callback invoked to update status.
 *
 * @return 0 on success, or -1/errno on failure.
 */
extern int
sync_interface_stats_open(int *read_fd, ws_process_id *fork_child, char **data, char **msg, void (*update_cb)(void));

/**
 * @brief Close an interface statistics stream previously opened with dumpcap.
 *
 * @param read_fd     File descriptor used to read statistics; closed on success.
 * @param fork_child  Process ID of the dumpcap child to terminate.
 * @param msg         On success NULL; on failure, an error message.
 *
 * @return 0 on success, or -1/errno on failure.
 */
extern int
sync_interface_stats_close(int *read_fd, ws_process_id *fork_child, char **msg);

/**
 * @brief Read a line from a pipe in non‑blocking mode.
 *
 * Attempts to read up to @p max bytes from @p pipe_fd into @p bytes without
 * blocking. A terminating NUL is not guaranteed to be added.
 *
 * @param pipe_fd  File descriptor of the pipe to read from.
 * @param bytes    Buffer into which data is read.
 * @param max      Maximum number of bytes to read.
 *
 * @return The number of bytes read, 0 if no data is available, or -1 on error.
 */
extern int
sync_pipe_gets_nonblock(int pipe_fd, char *bytes, int max);

/**
 * @brief Set a callback function to to be called with the PID of the forked child.
 *
 * @param cb Callback function that will be called with the PID of the dumpcap process.
 */
extern void capture_sync_set_fetch_dumpcap_pid_cb(void(*cb)(ws_process_id pid));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_SYNC_H__ */
