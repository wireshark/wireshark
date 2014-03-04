/* menus.h
 * Menu definitions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __MENUS_H__
#define __MENUS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Open a file(name)
   (will not ask to close existing capture file!) */
extern void menu_open_filename(gchar *cf_name);

/** @file
 *  Menubar and context menus.
 *  @ingroup main_window_group
 */

/** One of the name resolution menu items changed. */
extern void menu_name_resolution_changed(void);

/* Reset preferences menu on profile or preference change. */
extern void menu_prefs_reset(void);

extern void rebuild_visible_columns_menu (void);

/** Create a new menu.
 *
 * @param accel the created accelerator group
 * @return the new menu
 */
extern GtkWidget *main_menu_new(GtkAccelGroup **accel);

/** Set object data of menu, like g_object_set_data().
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
extern gboolean popup_menu_handler(GtkWidget *widget, GdkEvent *event, gpointer data);

/** The current file has changed, we need to update the file set menu items.
 *
 * @param file_set the current file is part of a file set
 * @param previous_file the previous file set (or NULL)
 * @param next_file the next file set (or NULL)
 */
extern void set_menus_for_file_set(gboolean file_set, gboolean previous_file, gboolean next_file);

/** The popup menu. */
extern GtkWidget           *popup_menu_object;

/* Update the packet list heading menu to indicate default
   column justification. */
void menus_set_column_align_default (gboolean right_justify);

/* Update the packet list heading menu to indicate if column can be resolved. */
void menus_set_column_resolved (gboolean resolved, gboolean can_resolve);

/* Fetch the statusbar profiles edit submenu */
extern GtkWidget *menus_get_profiles_rename_menu (void);

/* Fetch the statusbar profiles delete submenu */
extern GtkWidget *menus_get_profiles_delete_menu (void);

/* Fetch the statusbar profiles change submenu */
extern GtkWidget *menus_get_profiles_change_menu (void);

/* Enable or disable menu items based on whether a tree row is selected
   and and on whether a "Match Selected" can be done. */
void set_menus_for_selected_tree_row(capture_file *cf);

/* Enable or disable menu items based on whether a packet is selected. */
void set_menus_for_selected_packet(capture_file *cf);

/* Enable or disable menu items based on configuration profile */
void set_menus_for_profiles(gboolean default_profile);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENUS_H__ */
