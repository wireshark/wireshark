/* stream_prefs.h
 * Definitions for stream preferences window
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1999 Gerald Combs
 *
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

#ifndef __STREAM_PREFS_H__
#define __STREAM_PREFS_H__

/** @file
 *  "User Interface: Colors" preferences page.
 *  @todo rename functions and files from stream to colors
 *  @ingroup prefs_group
 */

/** Build a Colors preferences page.
 *
 * @return the new preferences page
 */
GtkWidget *stream_prefs_show(void);

/** Fetch preference values from page.
 *
 * @param widget widget from stream_prefs_show()
 */
void stream_prefs_fetch(GtkWidget *widget);

/** Apply preference values from page.
 *
 * @param widget widget from stream_prefs_show()
 */
void stream_prefs_apply(GtkWidget *widget);

/** Destroy preference values from page.
 *
 * @param widget widget from stream_prefs_show()
 */
void stream_prefs_destroy(GtkWidget *widget);

#endif
