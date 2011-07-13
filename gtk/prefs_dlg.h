/* prefs_dlg.h
 * Definitions for preference handling routines
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

#ifndef __PREFS_DLG_H__
#define __PREFS_DLG_H__

/** @defgroup prefs_group Preferences
 * 
 *  All GUI related preferences things. Please note, that some GUI related things 
 *  are saved in the recent file, which is processed in recent.h.
 *
 *  The Preference dialog has the following page submodules:
   @dot
  digraph prefs_pages {
      node [shape=record, fontname=Helvetica, fontsize=10];
      dialog [ label="Preferences dialog" URL="\ref prefs_dlg.h"];
      ui [ label="User Interface" URL="\ref prefs_gui.h"];
      layout [ label="UI: Layout" URL="\ref prefs_layout.h"];
      columns [ label="UI: Columns" URL="\ref prefs_column.h"];
      font [ label="UI: Font" URL="\ref prefs_gui.h"];
      colors [ label="UI: Colors" URL="\ref prefs_stream.h"];
      capture [ label="Capture" URL="\ref prefs_capture.h"];
      print [ label="Printing" URL="\ref prefs_print.h"];
      nameres [ label="Name resolution" URL="\ref prefs_nameres.h"];
      protocols [ label="Protocols" URL="\ref prefs_dlg.h"];
      dialog -> ui [ arrowhead="open", style="solid" ];
      dialog -> layout [ arrowhead="open", style="solid" ];
      dialog -> columns [ arrowhead="open", style="solid" ];
      dialog -> font [ arrowhead="open", style="solid" ];
      dialog -> colors [ arrowhead="open", style="solid" ];
      dialog -> capture [ arrowhead="open", style="solid" ];
      dialog -> print [ arrowhead="open", style="solid" ];
      dialog -> nameres [ arrowhead="open", style="solid" ];
      dialog -> protocols [ arrowhead="open", style="solid" ];
  }
  @enddot
 */

/** @file
 * "Preferences" and "Protocol properties" dialog boxes.
 *  @ingroup dialog_group
 *  @ingroup prefs_group
 */

typedef enum {
  PREFS_PAGE_USER_INTERFACE,
  PREFS_PAGE_LAYOUT,
  PREFS_PAGE_COLUMNS
} PREFS_PAGE_E;

/** Show the preferences dialog.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void prefs_cb(GtkWidget *widget, gpointer data);

/** Show the preferences dialog in given page.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 * @param prefs_page page to show
 */
extern void prefs_page_cb(GtkWidget *widget, gpointer data, PREFS_PAGE_E prefs_page);

/** Show the protocol properties dialog.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void properties_cb(GtkWidget *widget, gpointer data);

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

/** Create a static text for a preferences page.
 *
 * @param main_tb the table to put this entry into
 * @param table_position row in the table
 * @param label_text the label text
 * @param tooltip_text the tooltip for this text (not needed at all...)
 * @return the new static text label
 */
GtkWidget *
create_preference_static_text(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text);

/** Create a UAT button for a preferences page.
 *
 * @param main_tb the table to put this entry into
 * @param table_position row in the table
 * @param label_text the label text
 * @param tooltip_text the tooltip for this text
 * @param uat pointer to the UAT
 * @return the new UAT button
 */
GtkWidget *
create_preference_uat(GtkWidget *main_tb, int table_position,
    const gchar *label_text, const gchar *tooltip_text, void *uat);

/** Save all preferences */
void
prefs_main_write(void);

#endif
