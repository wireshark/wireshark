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
guint new_packet_list_append(column_info cinfo, gpointer fdata);
void new_packet_list_freeze(void);
void new_packet_list_thaw(void);
void new_packet_list_next(void);
void new_packet_list_prev(void);
void new_packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_);
gpointer new_packet_list_get_row_data(gint row);

#endif /* NEW_PACKET_LIST */

#endif /* __NEW_PACKET_LIST_H__ */
