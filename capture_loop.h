/* capture_loop.h
 * Do the low-level work of a capture
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
 *  Do the low-level work of a capture.
 *
 */

#ifndef __CAPTURE_LOOP_H__
#define __CAPTURE_LOOP_H__

/** Do the low-level work of a capture.
 *  Returns TRUE if it succeeds, FALSE otherwise. */
extern int  capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats);

/** Stop a low-level capture (stops the capture child). */
extern void capture_loop_stop(void);



/** Current Capture info. */
typedef struct {
    /* handles */
    gpointer        callback_data;  /**< capture callback handle */
    gpointer        ui;             /**< user interfaces own handle */

    /* capture info */
    packet_counts   *counts;        /**< protocol specific counters */
    time_t          running_time;   /**< running time since last update */
    gint            new_packets;    /**< packets since last update */
} capture_info;


/** Create the capture info dialog */
extern void capture_info_create(
capture_info    *cinfo,
gchar           *iface);

/** Update the capture info counters in the dialog */
extern void capture_info_update(
capture_info    *cinfo);

/** Destroy the capture info dialog again */
extern void capture_info_destroy(
capture_info    *cinfo);


#endif /* capture_loop.h */
