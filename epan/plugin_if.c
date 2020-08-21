/* plugin_if.c
 * An API for Wireshark plugins
 *
 * This enables wireshark dissectors, especially those implemented by plugins
 * to register menubar entries, which then will call a pre-defined callback
 * function for the dissector or plugin.
 *
 * Also it implements additional methods, which allow plugins to interoperate
 * with the main GUI.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <epan/epan.h>
#include <epan/proto.h>

#include "plugin_if.h"

static GList * menubar_entries = NULL;
static GList * menubar_menunames = NULL;

static GHashTable * plugin_if_callback_functions;

static void
plugin_if_init_hashtable(void)
{
    if ( plugin_if_callback_functions == 0 )
        plugin_if_callback_functions = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void plugin_if_call_gui_cb(plugin_if_callback_t actionType, GHashTable * dataSet)
{
    plugin_if_gui_cb action;

    plugin_if_init_hashtable();

    if ( g_hash_table_lookup_extended(plugin_if_callback_functions, GINT_TO_POINTER(actionType), NULL, (gpointer*)&action) )
    {
        if ( action != NULL )
            action(dataSet);
    }
}


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

    entry->parent_menu = 0;

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

extern ext_menu_t * ext_menubar_set_parentmenu(ext_menu_t * menu, const gchar * parentmenu)
{
    g_assert(menu != NULL && menu->parent == NULL);

    g_assert(parentmenu != 0);

    menu->parent_menu = g_strdup(parentmenu);

    return menu;
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
    ext_menubar_add_generic_entry ( EXT_MENUBAR_SEPARATOR, parent, "-", NULL, NULL, NULL );
}

/* Implementation of external toolbar handlers */

static GList * toolbar_entries = NULL;

extern GList * ext_toolbar_get_entries(void)
{
    return toolbar_entries;
}

ext_toolbar_t * ext_toolbar_register_toolbar(const gchar * toolbarlabel)
{
    ext_toolbar_t * entry = NULL;

    /* A name for the entry must be provided */
    g_assert(toolbarlabel != NULL && strlen ( toolbarlabel ) > 0 );

    entry = g_new0(ext_toolbar_t, 1);
    entry->type = EXT_TOOLBAR_BAR;

    /* Create a name for this toolbar */
    entry->name = g_strdup(toolbarlabel);
    entry->tooltip = g_strdup(toolbarlabel);

    entry->submenu_cnt = 0;
    entry->item_cnt = 0;

    toolbar_entries = g_list_append(toolbar_entries, entry);

    return entry;
}

static gint
ext_toolbar_compare(gconstpointer  a, gconstpointer  b)
{
    if ( !a || !b )
        return -1;

    const ext_toolbar_t * ta = (const ext_toolbar_t *)a;
    const ext_toolbar_t * tb = (const ext_toolbar_t *)b;

    return strcmp(ta->name, tb->name);
}

void ext_toolbar_unregister_toolbar_by_name(const gchar * toolbar_name)
{
    GList * walker = 0;

    if ( ! toolbar_name )
        return;

    walker = toolbar_entries;
    while ( walker && walker->data )
    {
        ext_toolbar_t * entry = (ext_toolbar_t *)walker->data;
        if ( g_strcmp0(entry->name, toolbar_name) == 0)
        {
            ext_toolbar_unregister_toolbar(entry);
            break;
        }

        walker = g_list_next(walker);
    }
}

void ext_toolbar_unregister_toolbar(ext_toolbar_t * toolbar)
{
    if ( ! toolbar )
        return;

    GList * entry = g_list_find_custom(toolbar_entries, toolbar, (GCompareFunc) ext_toolbar_compare);
    if ( entry && entry->data )
    {
        ext_toolbar_t * et = (ext_toolbar_t *)entry->data;
        toolbar_entries = g_list_remove(toolbar_entries, et);

        if ( ! g_list_find_custom(toolbar_entries, toolbar, (GCompareFunc) ext_toolbar_compare) )
        {
            GHashTable * dataSet = g_hash_table_new(g_str_hash, g_str_equal);
            g_hash_table_insert( dataSet, g_strdup("toolbar_name"), g_strdup(et->name) );
            plugin_if_call_gui_cb(PLUGIN_IF_REMOVE_TOOLBAR, dataSet);

            g_free(et->name);
            g_free(et->tooltip);
            g_free(et->defvalue);
            g_free(et->regex);

            g_free(et);
        }
    }
}

static gint
ext_toolbar_insert_sort(gconstpointer a, gconstpointer b)
{
    const ext_toolbar_t * ca = (const ext_toolbar_t *)a;
    const ext_toolbar_t * cb = (const ext_toolbar_t *)b;

    if ( ca == 0 || cb == 0 )
        return 0;

    /* Sort buttons after rest of objects */
    if ( ca->item_type == EXT_TOOLBAR_BUTTON && cb->item_type != EXT_TOOLBAR_BUTTON )
        return 1;
    else if ( ca->item_type != EXT_TOOLBAR_BUTTON && cb->item_type == EXT_TOOLBAR_BUTTON )
        return -1;
    else
    {
        if ( ca->item_cnt > cb->item_cnt )
            return 2;
        else if ( ca->item_cnt < cb->item_cnt )
            return -2;
        else
            return 0;
    }
}

ext_toolbar_t *
ext_toolbar_add_entry( ext_toolbar_t * parent, ext_toolbar_item_t type, const gchar *label,
        const gchar *defvalue, const gchar *tooltip, gboolean capture_only, GList * value_list,
        gboolean is_required, const gchar * regex, ext_toolbar_action_cb callback, gpointer user_data)
{
    ext_toolbar_t * entry = NULL;

    /* A valid parent must exist */
    g_assert(parent != NULL && parent->type == EXT_TOOLBAR_BAR);
    /* A label for the entry must be provided */
    g_assert(label != NULL && strlen ( label ) > 0 );
    /* A callback must be provided */
    g_assert(callback != NULL);

    parent->item_cnt++;

    /* Create menu entry */
    entry = g_new0(ext_toolbar_t, 1);
    entry->type = EXT_TOOLBAR_ITEM;
    entry->item_type = type;
    entry->item_cnt = g_list_length(parent->children) + 1;

    entry->name = g_strdup(label);

    if ( tooltip != NULL && strlen(tooltip) > 0 )
        entry->tooltip = g_strdup(tooltip);

    if ( defvalue != NULL && strlen(defvalue) > 0 )
        entry->defvalue = g_strdup(defvalue);

    if ( value_list != NULL && g_list_length(value_list) > 0 )
        entry->values = g_list_copy(value_list);

    entry->regex = g_strdup(regex);

    entry->is_required = is_required;
    entry->capture_only = capture_only;
    entry->callback = callback;
    entry->user_data = user_data;

    parent->children = g_list_insert_sorted(parent->children, entry, ext_toolbar_insert_sort);

    return entry;
}

static gint
ext_toolbar_search_label(gconstpointer tb, gconstpointer lbl)
{
    if ( ! tb || ! lbl )
        return -1;

    const ext_toolbar_t * toolbar = (const ext_toolbar_t *) tb;
    if ( toolbar->type != EXT_TOOLBAR_ITEM )
        return -2;

    const gchar * label = (const gchar * )lbl;

    return g_strcmp0(toolbar->name, label);
}

ext_toolbar_t * ext_toolbar_entry_by_label(const ext_toolbar_t * toolbar, const gchar * label)
{
    ext_toolbar_t * result = 0;
    GList * entry = g_list_find_custom(toolbar->children, label, ext_toolbar_search_label);
    if ( entry )
        result = (ext_toolbar_t *)entry->data;
    return result;
}

GList * ext_toolbar_add_val(GList * entries, gchar * value, gchar * display, gboolean is_default)
{
    ext_toolbar_value_t * newval = g_new0(ext_toolbar_value_t, 1);
    newval->value = g_strdup(value);
    newval->display = g_strdup(display);
    newval->is_default = is_default;

    return g_list_append(entries, newval);
}

typedef struct _ext_toolbar_update_entry_t
{
    ext_toolbar_action_cb callback;
    gpointer item_data;
} ext_toolbar_update_entry_t;

typedef struct _ext_toolbar_update_list_t
{
    ext_toolbar_t * item;
    GList * entries;
} ext_toolbar_update_list_t;

static gint
ext_toolbar_find_item(gconstpointer a, gconstpointer b)
{
    if ( a == 0 || b == 0 )
        return -1;

    const ext_toolbar_update_list_t * item = (const ext_toolbar_update_list_t *)a;
    const ext_toolbar_t * entry = (const ext_toolbar_t *)b;

    if ( item->item && g_strcmp0 ( item->item->name, entry->name ) == 0 )
        return 0;

    return -1;
}

static GList * toolbar_updates = NULL;

void ext_toolbar_register_update_cb(ext_toolbar_t * entry, ext_toolbar_action_cb callback, gpointer item_data)
{
    if ( entry == 0 || item_data == 0 || callback == 0 )
        return;

    ext_toolbar_update_list_t * update = NULL;
    GList * update_list = g_list_find_custom(toolbar_updates, entry, ext_toolbar_find_item);
    if ( ! update_list )
    {
        update = g_new0(ext_toolbar_update_list_t, 1);
        update->item = entry;
        toolbar_updates = g_list_append(toolbar_updates, update);
    }
    else
    {
        update = (ext_toolbar_update_list_t*)update_list->data;
    }

    ext_toolbar_update_entry_t * update_entry = g_new0(ext_toolbar_update_entry_t, 1);
    update_entry->callback = callback;
    update_entry->item_data = item_data;
    update->entries = g_list_append(update->entries, update_entry);
}

static void
ext_toolbar_update_entry(ext_toolbar_update_type_t update_type, ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent)
{
    GList * update = g_list_find_custom(toolbar_updates, entry, ext_toolbar_find_item);
    GList * walker = NULL;

    if ( ! update || ! update->data )
        return;

    ext_toolbar_update_t * update_data = g_new0(ext_toolbar_update_t, 1);
    update_data->user_data = data;
    update_data->data_index = idx;
    update_data->silent = silent;
    update_data->type = update_type;

    walker = ((ext_toolbar_update_list_t *)(update->data))->entries;

    while ( walker && walker->data )
    {
        ext_toolbar_update_entry_t * update_entry = (ext_toolbar_update_entry_t *)walker->data;
        /* Call Callback */
        if ( update_entry->callback && update_entry->item_data )
            update_entry->callback(entry, update_entry->item_data, update_data);
        walker = g_list_next(walker);
    }

    g_free(update_data);
}

void ext_toolbar_update_value(ext_toolbar_t * entry, gpointer data, gboolean silent)
{
    ext_toolbar_update_entry( EXT_TOOLBAR_UPDATE_VALUE, entry, data, NULL, silent );
}

void ext_toolbar_update_data(ext_toolbar_t * entry, gpointer data, gboolean silent)
{
    if ( entry->item_type == EXT_TOOLBAR_SELECTOR )
        ext_toolbar_update_entry( EXT_TOOLBAR_UPDATE_DATA, entry, data, NULL, silent );
}

void ext_toolbar_update_data_by_index(ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent)
{
    if ( entry->item_type == EXT_TOOLBAR_SELECTOR )
        ext_toolbar_update_entry( EXT_TOOLBAR_UPDATE_DATABYINDEX, entry, data, idx, silent );
}

void ext_toolbar_update_data_add_entry(ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent)
{
    if ( entry->item_type == EXT_TOOLBAR_SELECTOR )
        ext_toolbar_update_entry( EXT_TOOLBAR_UPDATE_DATA_ADD, entry, data, idx, silent );
}

void ext_toolbar_update_data_remove_entry(ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent)
{
    if ( entry->item_type == EXT_TOOLBAR_SELECTOR )
        ext_toolbar_update_entry( EXT_TOOLBAR_UPDATE_DATA_REMOVE, entry, data, idx, silent );
}

void ext_toolbar_update_data_set_active(ext_toolbar_t * entry, gboolean status)
{
    ext_toolbar_update_entry(EXT_TOOLBAR_SET_ACTIVE, entry, GINT_TO_POINTER(status ? 1 : 0), 0, TRUE );
}

/* Implementation of GUI callback methods follows.
 * This is a necessity, as using modern UI systems, gui interfaces often operate
 * in different threads then the calling application. Even more so, if the calling
 * application is implemented using a separate plugin. Therefore the external menubars
 * cannot call gui functionality directly, the gui has to perform the function within
 * it' own scope. */

extern void plugin_if_apply_filter(const char * filter_string, gboolean force)
{
    plugin_if_callback_t actionType;
    GHashTable * dataSet = NULL;

    actionType = ( force == TRUE ) ? PLUGIN_IF_FILTER_ACTION_APPLY : PLUGIN_IF_FILTER_ACTION_PREPARE;
    dataSet = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert( dataSet, g_strdup("action_type"), (gpointer) &actionType );
    g_hash_table_insert( dataSet, g_strdup("filter_string"), g_strdup(filter_string) );
    g_hash_table_insert( dataSet, g_strdup("force"), (gpointer) &force );

    plugin_if_call_gui_cb(actionType, dataSet);
}

extern void plugin_if_goto_frame(guint32 framenr)
{
    GHashTable * dataSet = NULL;

    dataSet = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert( dataSet, g_strdup("frame_nr"), GUINT_TO_POINTER(framenr) );

    plugin_if_call_gui_cb(PLUGIN_IF_GOTO_FRAME, dataSet);
}

extern void plugin_if_save_preference(const char * pref_module, const char * pref_key, const char * pref_value)
{
    GHashTable * dataSet = NULL;

    dataSet = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert( dataSet, g_strdup("pref_module"), g_strdup(pref_module) );
    g_hash_table_insert( dataSet, g_strdup("pref_key"), g_strdup(pref_key) );
    g_hash_table_insert( dataSet, g_strdup("pref_value"), g_strdup(pref_value) );

    plugin_if_call_gui_cb(PLUGIN_IF_PREFERENCE_SAVE, dataSet);
}

extern void plugin_if_get_ws_info(ws_info_t **ws_info_ptr)
{
    static ws_info_t ws_info = { FALSE, FILE_CLOSED, NULL, 0, 0, FALSE };
#ifdef HAVE_LIBPCAP

    GHashTable * dataSet;
    gchar * pluginKey = g_strdup("ws_info");

    dataSet = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert(dataSet, pluginKey, &ws_info);

    plugin_if_call_gui_cb(PLUGIN_IF_GET_WS_INFO, dataSet);

    g_hash_table_destroy(dataSet);
    g_free(pluginKey);

#else

    /* Initialise the ws_info structure */

    ws_info.ws_info_supported = FALSE;
    ws_info.cf_count = 0;
    ws_info.cf_filename = NULL;
    ws_info.cf_framenr = 0;
    ws_info.frame_passed_dfilter = FALSE;
    ws_info.cf_state = FILE_CLOSED;

#endif /* HAVE_LIBPCAP */

    *ws_info_ptr = &ws_info;
}

extern void* plugin_if_get_frame_data(plugin_if_frame_data_cb extract_cb, void* user_data) {
    GHashTable* dataSet = NULL;
    void* ret_value = NULL;

    dataSet = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert(dataSet, g_strdup("extract_cb"), extract_cb);
    g_hash_table_insert(dataSet, g_strdup("user_data"), user_data);
    g_hash_table_insert(dataSet, g_strdup("ret_value_ptr"), &ret_value);

    plugin_if_call_gui_cb(PLUGIN_IF_GET_FRAME_DATA, dataSet);

    g_hash_table_destroy(dataSet);

    return ret_value;
}

extern void* plugin_if_get_capture_file(plugin_if_capture_file_cb extract_cb, void* user_data) {
    GHashTable* dataSet = NULL;
    void* ret_value = NULL;

    dataSet = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert(dataSet, g_strdup("extract_cb"), extract_cb);
    g_hash_table_insert(dataSet, g_strdup("user_data"), user_data);
    g_hash_table_insert(dataSet, g_strdup("ret_value_ptr"), &ret_value);

    plugin_if_call_gui_cb(PLUGIN_IF_GET_CAPTURE_FILE, dataSet);

    g_hash_table_destroy(dataSet);

    return ret_value;
}

extern void plugin_if_register_gui_cb(plugin_if_callback_t actionType, plugin_if_gui_cb callback)
{
    plugin_if_init_hashtable();

    if ( ! g_hash_table_lookup_extended(plugin_if_callback_functions, GINT_TO_POINTER(actionType), NULL, NULL ) )
        g_hash_table_insert(plugin_if_callback_functions, GINT_TO_POINTER(actionType), (gpointer)callback);
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
