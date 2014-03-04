/* prefs_column.h
 * Definitions for column preferences window
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __COLUMN_PREFS_H__
#define __COLUMN_PREFS_H__

/** @file
 *  "User Interface: Columns" preferences page.
 *  @ingroup prefs_group
 */

/** Build a column preferences page.
 *
 * @return the new column preferences page
 */
GtkWidget           *column_prefs_show(GtkWidget *prefs_window);

/** Fetch preference values from page.
 *
 * @param widget widget from column_prefs_show()
 */
void                 column_prefs_fetch(GtkWidget *widget);

/** Apply preference values from page.
 *
 * @param widget widget from column_prefs_show()
 */
void                 column_prefs_apply(GtkWidget *widget);

/** Destroy preference values from page.
 *
 * @param widget widget from column_prefs_show()
 */
void                 column_prefs_destroy(GtkWidget *widget);

#endif
