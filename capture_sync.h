/* capture_sync.h
 * Synchronisation between Wireshark capture parent and child instances
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


/** @file
 *
 *  Sync mode capture (internal interface).
 *
 *  Will start a new Wireshark child instance which will do the actual capture
 *  work.
 */

#ifndef __CAPTURE_SYNC_H__
#define __CAPTURE_SYNC_H__

/**
 * Start a new capture session.
 *  Create a capture child which is doing the real capture work.
 *  The various capture_input_... functions will be called, if something had
 *  happened.
 *
 *  Most of the parameters are passed through the global capture_opts.
 *
 *  @param capture_opts the options
 *  @param cap_session a handle for the capture session
 *  @param update_cb update screen
 *  @return             TRUE if a capture could be started, FALSE if not
 */
extern gboolean
sync_pipe_start(capture_options *capture_opts, capture_session *cap_session, void(*update_cb)(void));

/** User wants to stop capturing, gracefully close the capture child */
extern void
sync_pipe_stop(capture_session *cap_session);

/** User wants to stop the program, just kill the child as soon as possible */
extern void
sync_pipe_kill(int fork_child);

/** Set wireless channel using dumpcap */
extern int
sync_interface_set_80211_chan(const gchar *iface, const char *freq, const gchar *type,
                              gchar **data, gchar **primary_msg,
                              gchar **secondary_msg, void (*update_cb)(void));

/** Get an interface list using dumpcap */
extern int
sync_interface_list_open(gchar **data, gchar **primary_msg,
                         gchar **secondary_msg, void (*update_cb)(void));

/** Get interface capabilities using dumpcap */
extern int
sync_if_capabilities_open(const gchar *ifname, gboolean monitor_mode,
                          gchar **data, gchar **primary_msg,
                          gchar **secondary_msg, void (*update_cb)(void));

/** Start getting interface statistics using dumpcap. */
extern int
sync_interface_stats_open(int *read_fd, int *fork_child, gchar **msg, void (*update_cb)(void));

/** Stop gathering statistics. */
extern int
sync_interface_stats_close(int *read_fd, int *fork_child, gchar **msg);

/** Read a line from a pipe, similar to fgets.  Non-blocking. */
extern int
sync_pipe_gets_nonblock(int pipe_fd, char *bytes, int max);

/*
 * Routines supplied by our caller; we call them back to notify them
 * of various events.
 *
 * XXX - this is *really* ugly.  We should do this better.
 */

/**
 * Capture child told us we have a new (or the first) capture file.
 */
extern gboolean
capture_input_new_file(capture_session *cap_session, gchar *new_file);

/**
 * Capture child told us we have new packets to read.
 */
extern void
capture_input_new_packets(capture_session *cap_session, int to_read);

/**
 * Capture child told us how many dropped packets it counted.
 */
extern void
capture_input_drops(capture_session *cap_session, guint32 dropped);

/**
 * Capture child told us that an error has occurred while starting the capture.
 */
extern void
capture_input_error_message(capture_session *cap_session, char *error_message,
                            char *secondary_error_msg);

/**
 * Capture child told us that an error has occurred while parsing a
 * capture filter when starting/running the capture.
 */
extern void
capture_input_cfilter_error_message(capture_session *cap_session, guint i,
                                    char *error_message);

/**
 * Capture child closed its side of the pipe, report any error and
 * do the required cleanup.
 */
extern void
capture_input_closed(capture_session *cap_session, gchar *msg);

/* set a callback to be called after fork with the pid of the forked child */
extern void capture_sync_set_fetch_dumpcap_pid_cb(void(*cb)(int pid));

#endif /* capture_sync.h */
