/* prefs_dlg.h
 * Definitions for preference handling routines
 *
 * $Id: prefs_dlg.h,v 1.8 2002/01/20 20:05:18 guy Exp $
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

#ifndef __PREFS_DLG_H__
#define __PREFS_DLG_H__

void       prefs_cb(GtkWidget *, gpointer);
void       properties_cb(GtkWidget *, gpointer);

GtkWidget *create_preference_check_button(GtkWidget *, int, const gchar *,
    const gchar *, gboolean);
GtkWidget *create_preference_radio_buttons(GtkWidget *, int, const gchar *,
    const gchar *, const enum_val_t *, gint);
gint fetch_preference_radio_buttons_val(GtkWidget *, const enum_val_t *);
GtkWidget *create_preference_option_menu(GtkWidget *, int, const gchar *,
    const gchar *, const enum_val_t *, gint);
gint fetch_preference_option_menu_val(GtkWidget *, const enum_val_t *);
GtkWidget *create_preference_entry(GtkWidget *, int, const gchar *,
    const gchar *, char *);

#endif
