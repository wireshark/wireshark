/* extcap_gtk.c
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

#ifndef __EXTCAP_GTK_H__
#define __EXTCAP_GTK_H__

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <gtk/gtk.h>

#include <extcap_parser.h>

/*
 * GObject data keys for linking argument records to the gtk
 * UI
 */
#define EXTCAP_GTK_DATA_KEY_ARGPTR      "EXTCAP_ARGPTR"
#define EXTCAP_GTK_DATA_KEY_VALPTR      "EXTCAP_VALPTR"
#define EXTCAP_GTK_DATA_KEY_FIRSTRADIO  "EXTCAP_FIRSTRADIO"
#define EXTCAP_GTK_DATA_KEY_WIDGETLIST  "EXTCAP_WIDGETLIST"
#define EXTCAP_GTK_DATA_KEY_TREEVIEW    "EXTCAP_TREEVIEW"
#define EXTCAP_GTK_DATA_KEY_FILENAME    "EXTCAP_FILENAME"
#define EXTCAP_GTK_DATA_KEY_ARGUMENT    "EXTCAP_ARGUMENT"

/*
 * GTK UI / EXTCAP Linkage:
 *
 * Packed vbox of widgets
 *      Contains EXTCAP_WIDGETLIST pointing to enclosed widget list
 *
 * GSList gtk_ui_widgets
 *      Linked list of drawable widgets in the UI
 *
 * GtkWidget contained in GSList
 *      Drawn GTK UI element.  If UI element is directly linked
 *      to argument, will contain EXTCAP_ARGPTR.
 *
 *      Top-level GTK widgets will include text boxes, sliders
 *      (if supported), and checkboxes.
 *
 *      If the top level widget contains radio buttons, it will
 *      contain an EXTCAP_ARGPTR *and* an EXTCAP_FIRSTRADIO
 *
 * Radio buttons
 *      Each radio button will contain an EXTCAP_VALPTR reference
 *      to the extcap_value * value being used.
 *
 * Selectors
 *      Each selector row contains a pointer to the value, in the
 *      column COL_VALUE
 *
 */

enum extcap_gtk_col_types {
    EXTCAP_GTK_COL_DISPLAY = 0, EXTCAP_GTK_COL_VALUE = 1, EXTCAP_GTK_NUM_COLS
};

enum extcap_gtk_multi_col_types {
    EXTCAP_GTK_MULTI_COL_CHECK = 0,
    EXTCAP_GTK_MULTI_COL_DISPLAY = 1,
    EXTCAP_GTK_MULTI_COL_VALUE = 2,
    EXTCAP_GTK_MULTI_COL_ACTIVATABLE = 3,
    EXTCAP_GTK_MULTI_NUM_COLS
};

/* Get a hash map of calls and values from the top widget */
GHashTable *extcap_gtk_get_state(GtkWidget *widget);

GtkWidget *extcap_create_gtk_rangewidget(extcap_arg *argument,
        GHashTable *prev_map);
GtkWidget *extcap_create_gtk_listwidget(extcap_arg *argument,
        GHashTable *prev_map);
GtkWidget *extcap_create_gtk_radiowidget(extcap_arg *argument,
        GHashTable *prev_map);
GtkWidget *extcap_create_gtk_multicheckwidget(extcap_arg *argument,
        GHashTable *prev_map);

/*
 * Populate a (pre-created) container widget based on an arguments record.
 * For secondary repopulations, a saved state can be passed to populate
 * with known values.  This should occur when setting interface options
 * repeatedly, for example
 */
GSList *extcap_populate_gtk_vbox(GList *arguments, GtkWidget *vbox,
        GHashTable *prev_map);

/* Free args associated with a GTK item */
void extcap_gtk_free_args(GtkWidget *vbox);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

