/* new_packet_list.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __NEW_PACKET_LIST_H__
#define __NEW_PACKET_LIST_H__

#include <gtk/gtk.h>

/** @file
 *  @ingroup main_window_group
 */

typedef enum {
  COLUMN_SELECTED_SORT_ASCENDING,
  COLUMN_SELECTED_SORT_DESCENDING,
  COLUMN_SELECTED_SORT_NONE,
  COLUMN_SELECTED_TOGGLE_RESOLVED,
  COLUMN_SELECTED_ALIGN_LEFT,
  COLUMN_SELECTED_ALIGN_CENTER,
  COLUMN_SELECTED_ALIGN_RIGHT,
  COLUMN_SELECTED_ALIGN_DEFAULT,
  COLUMN_SELECTED_RESIZE,
  COLUMN_SELECTED_CHANGE,
  COLUMN_SELECTED_HIDE,
  COLUMN_SELECTED_REMOVE
} COLUMN_SELECTED_E;

/** Create the packet list */
GtkWidget *new_packet_list_create(void);
/** Recreate the packetr list */
void new_packet_list_recreate(void);
void new_packet_list_toggle_visible_column (gint col_id);
void new_packet_list_set_all_columns_visible (void);
void new_packet_list_column_menu_cb (GtkWidget *w, gpointer data, COLUMN_SELECTED_E action);
void new_packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_);
gboolean new_packet_list_get_event_row_column(GdkEventButton *event_button, gint *physical_row, gint *row, gint *column);
guint new_packet_list_get_column_id (gint col_num);

/** Set the font of the packet list window.
 *
 * @param font new font
 */
extern void new_packet_list_set_font(PangoFontDescription *font);

/** Mark the currently selected packet.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_mark_frame_cb(GtkWidget *widget, gpointer data);

/** Toggle Mark on all displayed packets.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_toggle_mark_all_displayed_frames_cb(GtkWidget *w _U_, gpointer data _U_);

/** Mark all displayed packets.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_mark_all_displayed_frames_cb(GtkWidget *w _U_, gpointer data _U_);

/** UnMark all packets in the capture.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_unmark_all_displayed_frames_cb(GtkWidget *w _U_, gpointer data _U_);

/** Ignore the currently selected packet.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_ignore_frame_cb(GtkWidget *widget, gpointer data);

/** Ignore/Unignore all displayed packets.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_ignore_all_displayed_frames_cb(GtkWidget *w _U_, gpointer data _U_);

/** Un-ignore all packets in the list.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_unignore_all_frames_cb(GtkWidget *w _U_, gpointer data _U_);

/** Un-Time Reference all packets in the capture.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void new_packet_list_untime_reference_all_frames_cb(GtkWidget *w _U_, gpointer data _U_);

/** Different modes of copying summary data */
typedef enum {
    CS_TEXT, /**< Packet summary data (tab separated) */
    CS_CSV   /**< Packet summary data (comma separated) */
} copy_summary_type;

/** Called when user clicks on menu item to copy summary data.
 *
 *  @param w Not used.
 *  @param data Not used.
 *  @param copy_type Mode in which to copy data (e.g. tab-separated, CSV)
 */
void new_packet_list_copy_summary_cb(gpointer data _U_, copy_summary_type copy_type);

GtkWidget * new_packet_list_get_widget(void);
void new_packet_list_colorize_packets(void);

/** Set the selection mode of the packet list window.
 *
 * @param val TRUE for GTK_SELECTION_SINGLE, FALSE for GTK_SELECTION_BROWSE
 * @param force_set TRUE to force setting of the selection mode even if it
 *                  was already set (used within packet_list_recreate).
 */
extern void new_packet_list_set_sel_browse(gboolean val, gboolean force_set);

#endif /* __NEW_PACKET_LIST_H__ */
