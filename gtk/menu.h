/* menu.h
 * Menu definitions
 *
 * $Id: menu.h,v 1.17 2004/02/11 04:17:04 guy Exp $
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

/* Write all recent capture filenames to the user's recent file */
void menu_recent_file_write_all(FILE *rf);
void menu_open_recent_file_cmd(GtkWidget *w);
extern void menu_recent_read_finished(void);

GtkWidget *main_menu_new(GtkAccelGroup **);
void set_menu_object_data (gchar *path, gchar *key, gpointer data);
gint popup_menu_handler(GtkWidget *widget, GdkEvent *event, gpointer data);

extern GtkWidget           *popup_menu_object;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __GTKGUIMENU_H__ */
