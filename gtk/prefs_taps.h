/* prefs_taps.h
 * Definitions for Taps/Statistics preferences window
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

#ifndef __PREFS_STATS_H__
#define __PREFS_STATS_H__

/** @file
 *  "RTP player" preferences page.
 *  @ingroup prefs_group
 */

/** Build a RTP player preferences page.
 *
 * @return the new preferences page
 */
GtkWidget *stats_prefs_show(void);

/** Fetch preference values from page.
 *
 * @param widget widget from rtp_player_prefs_show()
 */
void stats_prefs_fetch(GtkWidget *widget);

/** Apply preference values from page.
 *
 * @param widget widget from rtp_player_prefs_show()
 */
void stats_prefs_apply(GtkWidget *widget);

/** Destroy preference values from page.
 *
 * @param widget widget from rtp_player_prefs_show()
 */
void stats_prefs_destroy(GtkWidget *widget);

#endif
