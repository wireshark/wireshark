/* find_dlg.h
 * Definitions for "find frame" window
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __FIND_DLG_H__
#define __FIND_DLG_H__

/** @file
 *  "Find" dialog box and related functions.
 *  @ingroup dialog_group
 */

/** User requested the "Find" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void find_frame_cb(GtkWidget *widget, gpointer data);

/** User requested the "Find Next" function.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void find_next_cb(GtkWidget *widget, gpointer data);

/** User requested the "Find Previous" function.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void find_previous_cb(GtkWidget *widget, gpointer data);

/** Find frame by filter.
 *
 * @param filter the filter string
 */
extern void find_frame_with_filter(char *filter);

/** Find next/previous frame by filter.
 *
 * @param filter the filter string
 * @param backwards TRUE, if searching should be done backwards
 */
extern void find_previous_next_frame_with_filter(const char *filter, gboolean backwards);

#endif /* find_dlg.h */
