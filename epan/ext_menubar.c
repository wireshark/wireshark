/* ext_menubar.c
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

#include "config.h"

#include <glib.h>
#include <epan/epan.h>
#include <epan/proto.h>

#include "ext_menubar.h"

static GList * menubar_entries = NULL;
static GList * menubar_menunames = NULL;

extern GList * ext_menubar_get_entries(void)
{
    return menubar_entries;
}

extern ext_menu_t * ext_menubar_register_menu(int proto_id, const gchar * menulabel,
        gboolean is_plugin)
{
    ext_menubar_t * entry = NULL;
    gchar * name = NULL;

    /* A name for the entry must be provided */
    g_assert(menulabel != NULL && strlen ( menulabel ) > 0 );

    /* A protocol must exist for the given id */
    g_assert(find_protocol_by_id(proto_id) != NULL);

    /* Create unique name, which is used by GTK to provide the menu */
    name = g_strconcat(proto_get_protocol_filter_name(proto_id), "Menu", NULL);

    /* For now, a protocol may only register one main menu */
    g_assert(g_list_find(menubar_menunames, name) == NULL);

    entry = (ext_menubar_t *)g_malloc0(sizeof(ext_menubar_t));
    entry->type = EXT_MENUBAR_MENU;
    entry->proto = proto_id;
    entry->is_plugin = is_plugin;

    /* Create a name for this submenu */
    entry->name = name;
    entry->label = g_strdup(menulabel);
    entry->tooltip = g_strdup(menulabel);

    entry->submenu_cnt = 0;
    entry->item_cnt = 0;

    menubar_entries = g_list_append(menubar_entries, entry);
    menubar_menunames = g_list_append(menubar_menunames, name);

    return entry;
}

extern ext_menu_t * ext_menubar_add_submenu(ext_menu_t * parent, const gchar *menulabel)
{
    ext_menubar_t * entry = NULL;

    /* A name for the entry must be provided */
    g_assert(menulabel != NULL && strlen ( menulabel ) > 0 );

    /* Parent must be a valid parent */
    g_assert(parent != NULL && parent->type == EXT_MENUBAR_MENU);

    parent->submenu_cnt++;

    /* Create submenu entry */
    entry = (ext_menubar_t *)g_malloc0(sizeof(ext_menubar_t));
    entry->type = EXT_MENUBAR_MENU;
    entry->parent = parent;
    /* Just a convenience */
    entry->proto = parent->proto;
    entry->is_plugin = parent->is_plugin;
    /* Create unique name, which is used by GTK to provide the menu */
    entry->name = g_strdup_printf("%sS%02d", parent->name, parent->submenu_cnt);
    entry->label = g_strdup(menulabel);
    entry->tooltip = g_strdup(menulabel);

    parent->children = g_list_append(parent->children, entry);

    return entry;
}

static void ext_menubar_add_generic_entry (
        ext_menubar_entry_t type, ext_menu_t * parent, const gchar * label,
        const gchar * tooltip, ext_menubar_action_cb callback, gpointer user_data )
{
    ext_menubar_t * entry = NULL;

    /* A valid parent must exist */
    g_assert(parent != NULL && parent->type == EXT_MENUBAR_MENU);
    /* A label for the entry must be provided */
    g_assert(label != NULL && strlen ( label ) > 0 );

    parent->item_cnt++;

    /* Create menu entry */
    entry = (ext_menubar_t*)g_malloc0(sizeof(ext_menubar_t));
    entry->type = type;
    /* Create unique name, which is used by GTK to provide the menu */
    entry->name = g_strdup_printf("%sI%02d", parent->name, parent->item_cnt);
    entry->label = g_strdup(label);

    if ( tooltip != NULL && strlen(tooltip) > 0 )
        entry->tooltip = g_strdup(tooltip);

    entry->callback = callback;
    entry->user_data = user_data;

    parent->children = g_list_append(parent->children, entry);
}

extern void ext_menubar_add_entry(ext_menu_t * parent, const gchar *label,
        const gchar *tooltip, ext_menubar_action_cb callback, gpointer user_data)
{
    /* A callback must be provided */
    g_assert(callback != NULL);

    ext_menubar_add_generic_entry ( EXT_MENUBAR_ITEM, parent, label, tooltip, callback, user_data );
}

extern void ext_menubar_add_website(ext_menu_t * parent, const gchar *label,
        const gchar *tooltip, const gchar *url)
{
    /* An url for the entry must be provided */
    g_assert(url != NULL && strlen ( url ) > 0 );

    ext_menubar_add_generic_entry ( EXT_MENUBAR_URL, parent, label, tooltip, NULL, (gpointer) g_strdup(url) );
}

extern void ext_menubar_add_separator(ext_menu_t *parent)
{
    ext_menubar_add_generic_entry ( EXT_MENUBAR_SEPARATOR, parent, g_strdup("-"), NULL, NULL, NULL );
}

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
