/* packet_list.h
 * Declarations of GTK+-specific routines for managing the packet list.
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

#ifndef __PACKET_LIST_H__
#define __PACKET_LIST_H__

/** @file
 *  Packet list pane.
 *  @ingroup main_window_group
 */

/** Create a new packet list.
 *
 * @param prefs current preferences
 * @return the new packet list
 */
extern GtkWidget *packet_list_new(e_prefs *prefs);

/** Fill in column titles.  This must be done after the top level window
 *  is displayed.
 *
 * @todo is that still true, with fixed-width columns?
 */
extern void packet_list_set_column_titles(void);

/** Resize columns
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void packet_list_resize_columns_cb(GtkWidget *widget, gpointer data);

/** Mark the currently selected packet.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void packet_list_mark_frame_cb(GtkWidget *widget, gpointer data);

/** Mark all packets in the list.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void packet_list_mark_all_frames_cb(GtkWidget *widget, gpointer data);

/** Unmark all packets in the list.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void packet_list_unmark_all_frames_cb(GtkWidget *widget, gpointer data);

/** Update packet marks. */
extern void packet_list_update_marked_frames(void);

/** Gdk button click appeared, get row and column number in packet list from that position.
 * 
 * @param widget the packet list widget from packet_list_new()
 * @param event_button the button event clicked
 * @param row the row in the packet list
 * @param column the column in the packet list
 * @return TRUE if row/column is returned and in range
 */
extern gboolean packet_list_get_event_row_column(GtkWidget *widget,
    GdkEventButton *event_button, gint *row, gint *column);

/** Set the font of the packet list.
 *
 * @param font the new font
 */
extern void packet_list_set_font(FONT_TYPE *font);

/** Set the selection mode of the packet list window.
 *
 * @param val TRUE for GTK_SELECTION_SINGLE, FALSE for GTK_SELECTION_BROWSE
 */
extern void packet_list_set_sel_browse(gboolean val);

#endif /* __PACKET_LIST_H__ */
