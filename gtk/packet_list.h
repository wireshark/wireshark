/* packet_list.h
 * Declarations of GTK+-specific routines for managing the packet list.
 *
 * $Id: packet_list.h,v 1.2 2004/01/19 00:42:10 ulfl Exp $
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

extern GtkWidget *packet_list_new(e_prefs *prefs);
extern void packet_list_set_column_titles(void);

extern void mark_frame_cb(GtkWidget *, gpointer);
extern void mark_all_frames_cb(GtkWidget *w, gpointer);
extern void unmark_all_frames_cb(GtkWidget *w, gpointer);
extern void update_marked_frames(void);

extern gboolean packet_list_get_event_row_column(GtkWidget *w,
    GdkEventButton *event_button, gint *row, gint *column);

#if GTK_MAJOR_VERSION < 2
extern void set_plist_font(GdkFont *font);
#else
extern void set_plist_font(PangoFontDescription *font);
#endif

extern void set_plist_sel_browse(gboolean);

#endif /* __PACKET_LIST_H__ */
