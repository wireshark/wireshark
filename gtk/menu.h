/* menu.h
 * Menu definitions
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

#ifndef __GTKGUIMENU_H__
#define __GTKGUIMENU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
extern void set_menu_object_data(gchar *path, gchar *key, gpointer data);

/** The popup menu handler.
 *
 * @param widget the parent widget
 * @param event the GdkEvent
 * @param data the corresponding menu 
 */
extern gint popup_menu_handler(GtkWidget *widget, GdkEvent *event, gpointer data);

/** The popup menu. */
extern GtkWidget           *popup_menu_object;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __GTKGUIMENU_H__ */
