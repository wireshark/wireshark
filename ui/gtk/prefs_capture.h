/* capture_prefs.h
 * Definitions for capture preferences window
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

#ifndef __CAPTURE_PREFS_H__
#define __CAPTURE_PREFS_H__

/** @file
 *  "Capture" preferences page.
 *  @ingroup prefs_group
 */

/** Build a capture preferences page.
 *
 * @return the new capture preferences page
 */
GtkWidget *capture_prefs_show(void);

/** Fetch preference values from page.
 *
 * @param widget widget from capture_prefs_show()
 */
void capture_prefs_fetch(GtkWidget *widget);

/** Apply preference values from page.
 *
 * @param widget widget from capture_prefs_show()
 */
void capture_prefs_apply(GtkWidget *widget);

/** Destroy preference values from page.
 *
 * @param widget widget from capture_prefs_show()
 */
void capture_prefs_destroy(GtkWidget *widget);

#endif
