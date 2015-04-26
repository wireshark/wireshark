/* ext_menubar.h
 * A menubar API for Wireshark dissectors
 *
 * This enables wireshark dissectors, especially those implemented by plugins
 * to register menubar entries, which then will call a pre-defined callback
 * function for the dissector or plugin
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
#ifndef EPAN_EXT_MENUBAR_H_
#define EPAN_EXT_MENUBAR_H_

#include <config.h>

#include "ws_symbol_export.h"

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet_info.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define EXT_MENUBAR_MAX_DEPTH 5

typedef enum
{
    EXT_MENUBAR_GTK_GUI,
    EXT_MENUBAR_QT_GUI
} ext_menubar_gui_type;

/* menubar callback */
typedef void (*ext_menubar_action_cb)(ext_menubar_gui_type gui_type, gpointer gui_object, gpointer user_data);

typedef enum
{
    EXT_MENUBAR_MENU,
    EXT_MENUBAR_ITEM,
    EXT_MENUBAR_SEPARATOR,
    EXT_MENUBAR_URL
} ext_menubar_entry_t;

typedef struct _ext_menubar_t ext_menubar_t;
typedef ext_menubar_t ext_menu_t;

struct _ext_menubar_t
{
    ext_menubar_entry_t type;
    ext_menu_t * parent;
    int proto;
    GList * children;
    guint submenu_cnt;
    guint item_cnt;

    gchar * name;
    gchar * label;

    gchar * tooltip;
    gboolean is_plugin;
    gpointer user_data;

    ext_menubar_action_cb callback;


};

/* Registers a new main menu.
 *
 * This will register a new main menu entry, underneath all other menu entries will
 * be sorted
 *
 * @param proto_id the proto item for the protocol this menu entry belongs too
 * @param name the entry name (the internal used one) for the menu item
 * @param menulabel the entry label (the displayed name) for the menu item
 * @param is_plugin must be set to TRUE for plugin registration
 */
WS_DLL_PUBLIC ext_menu_t * ext_menubar_register_menu(
        int proto_id, const gchar * menulabel, gboolean is_plugin);

/* Registers a new main menu.
 *
 * This will register a new sub menu entry, underneath the parent menu
 *
 * @param parent the parent menu for this submenu
 * @param name the entry name (the internal used one) for the menu item
 * @param menulabel the entry label (the displayed name) for the menu item
 */
WS_DLL_PUBLIC ext_menu_t * ext_menubar_add_submenu(
        ext_menu_t * parent, const gchar *menulabel);

/* Registers a new menubar entry.
 *
 * This registers a new menubar entry, which will have the given name, and
 * call the provided callback on activation
 *
 * @param parent_menu the parent menu for this entry
 * @param name the entry name (the internal used one) for the menu item
 * @param label the entry label (the displayed name) for the menu item
 * @param tooltip a tooltip to be displayed on mouse-over
 * @param callback the action which will be invoked after click on the menu item
 */
WS_DLL_PUBLIC void ext_menubar_add_entry(
        ext_menu_t * parent_menu,
        const gchar *label,
        const gchar *tooltip,
        ext_menubar_action_cb callback,
        gpointer user_data);

/* Registers a new separator entry.
 *
 * @note This will not work using the legacy GTK interface, due to
 * restrictions on how separators are handled in the menu
 *
 * @param parent_menu the parent menu for this entry
 */
WS_DLL_PUBLIC void ext_menubar_add_separator(ext_menu_t *parent_menu);

/* Registers a entry for a website call
 *
 * This registers a new menubar entry, which will call the given website, using
 * the predefined webbrowser
 *
 * @param parent_menu the parent menu for this entry
 * @param name the entry name (the internal used one) for the menu item
 * @param label the entry label (the displayed name) for the menu item
 * @param tooltip a tooltip to be displayed on mouse-over
 * @param url the url for the website
 */
WS_DLL_PUBLIC void ext_menubar_add_website(ext_menu_t * parent, const gchar *label,
        const gchar *tooltip, const gchar *url);

/* Private Method for retrieving the menubar entries
 *
 * Is only to be used by the UI interfaces to retrieve the menu entries
 */
WS_DLL_PUBLIC GList * ext_menubar_get_entries(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EPAN_EXT_MENUBAR_H_ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
