/* menu.h
 * Menu definitions
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

#ifndef __GTKGUIMENU_H__
#define __GTKGUIMENU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern void add_menu_recent_capture_file(gchar *cf_name);

/** @file
 *  Menubar and context menus.
 *  @ingroup main_window_group
 */

/** Write all recent capture filenames to the user's recent file.
 * @param rf recent file
 */
extern void menu_recent_file_write_all(FILE *rf);

/** User pushed a recent file submenu item.
 *
 * @param widget parent widget
 */
extern void menu_open_recent_file_cmd(GtkWidget *widget);

/** The recent file read has finished, update the menu corresponding. */
extern void menu_recent_read_finished(void);

/** One of the name resolution menu items changed. */
extern void menu_name_resolution_changed(void);

/** The "Colorize Packet List" option changed. */
extern void menu_colorize_changed(gboolean packet_list_colorize);

#ifdef HAVE_LIBPCAP
/** The "Auto Scroll Packet List in Live Capture" option changed. */
extern void menu_auto_scroll_live_changed(gboolean auto_scroll_in);
#endif

/** Create a new menu.
 *
 * @param accel the created accelerator group
 * @return the new menu
 */
extern GtkWidget *main_menu_new(GtkAccelGroup **accel);

/** Set object data of menu, like OBJECT_SET_DATA().
 *
 * @param path the path of the menu item
 * @param key the key to set
 * @param data the data to set
 */
extern void set_menu_object_data(const gchar *path, const gchar *key, gpointer data);

/** The popup menu handler.
 *
 * @param widget the parent widget
 * @param event the GdkEvent
 * @param data the corresponding menu 
 */
extern gint popup_menu_handler(GtkWidget *widget, GdkEvent *event, gpointer data);

/** The packet history has changed, we need to update the menu.
 *
 * @param back_history some back history entries available
 * @param forward_history some forward history entries available
 */
extern void set_menus_for_packet_history(gboolean back_history, gboolean forward_history);

/** The current file has changed, we need to update the file set menu items.
 *
 * @param file_set the current file is part of a file set
 * @param previous_file the previous file set (or NULL)
 * @param next_file the next file set (or NULL)
 */
extern void set_menus_for_file_set(gboolean file_set, gboolean previous_file, gboolean next_file);

/** The popup menu. */
extern GtkWidget           *popup_menu_object;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __GTKGUIMENU_H__ */
