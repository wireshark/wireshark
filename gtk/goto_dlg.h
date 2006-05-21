/* goto_dlg.h
 * Definitions for "go to frame" window
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

#ifndef __GOTO_DLG_H__
#define __GOTO_DLG_H__

/** @file
 * "Go To" dialog box and similar functions.
 *  @ingroup dialog_group
 */

/** User requested the "Go To" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void goto_frame_cb(GtkWidget *widget, gpointer data);

/** User requested "Go To Corresponding Packet" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void goto_framenum_cb(GtkWidget *widget, gpointer data);

/** User requested "Go To First Packet" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void goto_top_frame_cb(GtkWidget *widget, gpointer data);

/** User requested "Go To Last Packet" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void goto_bottom_frame_cb(GtkWidget *widget, gpointer data);

#endif /* goto_dlg.h */
