/* menu.h
 * Menu definitions
 *
 * $Id: menu.h,v 1.4 1998/12/17 05:42:27 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __MENU_H__
#define __MENU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


void menus_init(void);

#ifdef GTK_HAVE_FEATURES_1_1_0
void get_main_menu (GtkWidget **, GtkAccelGroup **);
#else
void get_main_menu (GtkWidget **, GtkAcceleratorTable **);
#endif
void set_menu_sensitivity (gchar *, gint);
void set_menu_object_data (gchar *path, gchar *key, gpointer data);
void menus_create (GtkMenuEntry *, int);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENU_H__ */
