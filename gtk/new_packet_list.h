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

#ifdef NEW_PACKET_LIST
#include <gtk/gtk.h>

#define RECENT_KEY_COL_WIDTH                "column.width"

GtkWidget *new_packet_list_create(void);
void new_packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_);
gboolean new_packet_list_get_event_row_column(GdkEventButton *event_button, gint *physical_row, gint *row, gint *column);

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

void new_packet_list_mark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_);
void new_packet_list_unmark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_);

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
void new_packet_list_copy_summary_cb(GtkWidget * w _U_, gpointer data _U_, copy_summary_type copy_type);

/** Write all packet list geometry values to the recent file.
 *
 *  @param rf recent file handle from caller
 */
extern void new_packet_list_recent_write_all(FILE *rf);

GtkWidget * new_packet_list_get_widget(void);
void new_packet_list_colorize_packets(void);

#endif /* NEW_PACKET_LIST */

#endif /* __NEW_PACKET_LIST_H__ */
