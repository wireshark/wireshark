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

#endif /* NEW_PACKET_LIST */

#endif /* __NEW_PACKET_LIST_H__ */
