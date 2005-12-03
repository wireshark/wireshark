/* capture_sync.h
 * Synchronisation between Ethereal capture parent and child instances
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 *  Will start a new Ethereal child instance which will do the actual capture 
 *  work.
 */

#ifndef __CAPTURE_SYNC_H__
#define __CAPTURE_SYNC_H__

/** Name we give to the child process when doing a "-S" capture. */
#define	CHILD_NAME	"ethereal-capture"


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
sync_pipe_kill(capture_options *capture_opts);


/** the child has opened a new capture file, notify the parent */
extern void
sync_pipe_filename_to_parent(const char *filename);

/** the child captured some new packets, notify the parent */
extern void
sync_pipe_packet_count_to_parent(int packet_count);

/** the child stopped capturing, notify the parent */
extern void
sync_pipe_drops_to_parent(int drops);

/** the child encountered an error, notify the parent */
extern void 
sync_pipe_errmsg_to_parent(const char *errmsg);


#endif /* capture_sync.h */
