/* prefs_font_color.h
 * Definitions for stream preferences window
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PREFS_FONT_COLOR_H__
#define __PREFS_FONT_COLOR_H__

/** @file
 *  "User Interface: Colors" preferences page.
 *  @todo rename functions and files from stream to colors
 *  @ingroup prefs_group
 */

/** Build a Font and Colors preferences page.
 *
 * @return the new preferences page
 */
GtkWidget *font_color_prefs_show(void);

/** Fetch preference values from page.
 *
 * @param widget widget from font_color_prefs_show()
 */
void font_color_prefs_fetch(GtkWidget *widget);

/** Apply preference values from page.
 *
 * @param widget widget from font_color_prefs_show()
 */
void font_color_prefs_apply(GtkWidget *widget, gboolean);

/** Destroy preference values from page.
 *
 * @param widget widget from font_color_prefs_show()
 */
void font_color_prefs_destroy(GtkWidget *widget);

#endif /* __PREFS_FONT_COLOR__ */
