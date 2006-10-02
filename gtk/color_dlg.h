/* color_dlg.h
 * Definitions for dialog boxes for color filters
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

#ifndef __COLOR_DLG_H__
#define __COLOR_DLG_H__

/** @file
 *  "Colorize Display" dialog box.
 *  @ingroup dialog_group
 */

/** User requested the "Colorize Display" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void color_display_cb(GtkWidget *widget, gpointer data);

/** Open the colorize dialogue and presets the filter string.
 *
 * @param filter the preset filter string
 */
void color_display_with_filter(char *filter);

/** Count the number of selected color filters.
 *
 * @return the number of selected color filters
 */
int color_selected_count(void);

#endif /* color_dlg.h */
