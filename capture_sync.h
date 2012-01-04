/* capture_sync.h
 * Synchronisation between Wireshark capture parent and child instances
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
 *  @return             TRUE if a capture could be started, FALSE if not
 */
extern gboolean
sync_pipe_start(capture_options *capture_opts);

/** User wants to stop capturing, gracefully close the capture child */
extern void
sync_pipe_stop(capture_options *capture_opts);

/** User wants to stop the program, just kill the child as soon as possible */
extern void
sync_pipe_kill(int fork_child);

/** Get an interface list using dumpcap */
extern int
sync_interface_list_open(gchar **data, gchar **primary_msg,
                         gchar **secondary_msg);

/** Get interface capabilities using dumpcap */
extern int
sync_if_capabilities_open(const gchar *ifname, gboolean monitor_mode,
                          gchar **data, gchar **primary_msg,
                          gchar **secondary_msg);

/** Start getting interface statistics using dumpcap. */
extern int
sync_interface_stats_open(int *read_fd, int *fork_child, gchar **msg);

/** Stop gathering statistics. */
extern int
sync_interface_stats_close(int *read_fd, int *fork_child, gchar **msg);

/** Read a line from a pipe, similar to fgets.  Non-blocking. */
extern int
sync_pipe_gets_nonblock(int pipe_fd, char *bytes, int max);


#endif /* capture_sync.h */
