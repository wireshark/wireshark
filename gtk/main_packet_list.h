/* main_packet_list.h
 * Declarations of GTK+-specific routines for managing the packet list.
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

#ifndef __PACKET_LIST_H__
#define __PACKET_LIST_H__

#define RECENT_KEY_COL_WIDTH                "column.width"

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

/** Recreate the packet list (for use after columns are changed) */
extern void packet_list_recreate(void);

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
extern void packet_list_set_font(PangoFontDescription *font);

/** Set the selection mode of the packet list window.
 *
 * @param val TRUE for GTK_SELECTION_SINGLE, FALSE for GTK_SELECTION_BROWSE
 * @param force_set TRUE to force setting of the selection mode even if it
 *                  was already set (used within packet_list_recreate).
 */
extern void packet_list_set_sel_browse(gboolean val, gboolean force_set);

/** Move to the next packet
 */
extern void packet_list_next(void);

/** Move to the previous packet
 */
extern void packet_list_prev(void);

/** Check to see if the packet list is at its end.  Toggles automatic
 * scrolling if needed.
 *
 * @return TRUE if packet list is scrolled to greater than 90% of its total length.
 */
extern gboolean packet_list_check_end(void);

/* Different modes of copying summary data */
typedef enum {
    CS_TEXT, /* Packet summary data (tab separated) */
    CS_CSV   /* Packet summary data (comma separated) */
} copy_summary_type;

/** Called when user clicks on menu item to copy summary data.
 *
 *  @param w Not used.
 *  @param data Not used.
 *  @param copy_type Mode in which to copy data (e.g. tab-separated, CSV)
 */
extern void packet_list_copy_summary_cb(GtkWidget * w _U_, gpointer data _U_, copy_summary_type copy_type);

/** Write all packet list geometry values to the recent file.
 *
 *  @param rf recent file handle from caller
 */
extern void packet_list_recent_write_all(FILE *rf);

#endif /* __PACKET_LIST_H__ */
