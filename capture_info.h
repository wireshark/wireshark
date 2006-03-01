/* capture_info.h
 * capture info functions
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
 * capture info functions
 *
 */

#ifndef __CAPTURE_INFO_H__
#define __CAPTURE_INFO_H__


/* open the info - init values (wtap, counts), create dialog */
extern void capture_info_open(const char *iface);

/* new file arrived - (eventually close old wtap), open wtap */
extern gboolean capture_info_new_file(const char *new_filename);

/* new packets arrived - read from wtap, count */
extern void capture_info_new_packets(int to_read);

/* close the info - close wtap, destroy dialog */
extern void capture_info_close(void);



/** Current Capture info. */
typedef struct {
    /* handle */
    gpointer        ui;             /**< user interface handle */

    /* capture info */
    packet_counts   *counts;        /**< protocol specific counters */
    time_t          running_time;   /**< running time since last update */
    gint            new_packets;    /**< packets since last update */
} capture_info;


/** Create the capture info dialog */
extern void capture_info_ui_create(
capture_info    *cinfo,
const gchar     *iface);

/** Update the capture info counters in the dialog */
extern void capture_info_ui_update(
capture_info    *cinfo);

/** Destroy the capture info dialog again */
extern void capture_info_ui_destroy(
capture_info    *cinfo);


#endif /* capture_info.h */
