/* prefs_dlg.h
 * Definitions for preference handling routines
 *
 * $Id: prefs_dlg.h,v 1.11 2004/06/02 18:44:10 ulfl Exp $
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

/** @file
 * "Preferences" and "Protocol properties" dialog boxes.
 */

/** Show the preferences dialog.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void prefs_cb(GtkWidget *widget, gpointer data);

/** Show the protocol properties dialog.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void properties_cb(GtkWidget *widget, gpointer data);

#define E_TOOLTIPS_KEY "tooltips"

/** Create a check button for a preferences page.
 *
 * @param main_tb the table to put this button into
 * @param table_row row in the table
 * @param label_text the label text for the left side
 * @param tooltip_text the tooltip for this check button
 * @param active the check button is initially active
 * @return the new check button
 */
extern GtkWidget *create_preference_check_button(GtkWidget *main_tb, int table_row,
    const gchar *label_text, const gchar *tooltip_text, gboolean active);

/** Create a radio button for a preferences page.
 *
 * @param main_tb the table to put this button into
 * @param table_row row in the table
 * @param label_text the label text for the left side
 * @param tooltip_text the tooltip for this radio button
 * @param enumvals the values
 * @param current_val the initially selected value
 * @return the new radio button
 */
extern GtkWidget *create_preference_radio_buttons(GtkWidget *main_tb, int table_row,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val);

/** Get the currently selected value from a radio button.
 * 
 * @param button the button from create_preference_radio_buttons()
 * @param enumvals the same enum vals as in create_preference_radio_buttons()
 * @return the index of the currently selected item
 */
extern gint fetch_preference_radio_buttons_val(GtkWidget *button, const enum_val_t *enumvals);

/** Create an option menu for a preferences page.
 *
 * @param main_tb the table to put this menu into
 * @param table_row row in the table
 * @param label_text the label text for the left side
 * @param tooltip_text the tooltip for this option menu
 * @param enumvals the values
 * @param current_val the initially selected value
 * @return the new option menu
 */
extern GtkWidget *create_preference_option_menu(GtkWidget *main_tb, int table_row,
    const gchar *label_text, const gchar *tooltip_text,
    const enum_val_t *enumvals, gint current_val);

/** Get the currently selected value from an option menu.
 * 
 * @param optmenu the option menu from create_preference_option_menu()
 * @param enumvals the same enum vals as in create_preference_option_menu()
 * @return the index of the currently selected item
 */
extern gint fetch_preference_option_menu_val(GtkWidget *optmenu, const enum_val_t *enumvals);

/** Create a text entry for a preferences page.
 *
 * @param main_tb the table to put this entry into
 * @param table_row row in the table
 * @param label_text the label text for the left side
 * @param tooltip_text the tooltip for this text entry
 * @param value the initially value
 * @return the new text entry
 */
extern GtkWidget *create_preference_entry(GtkWidget *main_tb, int table_row,
    const gchar *label_text, const gchar *tooltip_text, char *value);

#endif
