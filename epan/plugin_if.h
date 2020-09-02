/* plugin_if.h
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
#ifndef EPAN_PLUGIN_IF_H
#define EPAN_PLUGIN_IF_H

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#include <glib.h>
#include <epan/epan.h>
#include <epan/packet_info.h>
#include <cfile.h>

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

    gchar * parent_menu;
};

typedef void (*ext_toolbar_action_cb)(gpointer toolbar_item, gpointer item_data, gpointer user_data);

typedef enum
{
    EXT_TOOLBAR_BAR,
    EXT_TOOLBAR_ITEM
} ext_toolbar_entry_t;

typedef enum
{
    EXT_TOOLBAR_BOOLEAN,
    EXT_TOOLBAR_BUTTON,
    EXT_TOOLBAR_STRING,
    EXT_TOOLBAR_SELECTOR
} ext_toolbar_item_t;

typedef struct _ext_toolbar_value_t
{
    gchar * value;
    gchar * display;

    gboolean is_default;

} ext_toolbar_value_t;

typedef struct _ext_toolbar_t
{
    ext_toolbar_entry_t type;

    GList * children;
    guint submenu_cnt;
    guint item_cnt;

    gchar * name;
    gchar * defvalue;
    gchar * tooltip;
    gpointer user_data;

    gboolean is_required;
    gboolean capture_only;
    ext_toolbar_item_t item_type;

    GList * values;
    gchar * regex;

    ext_toolbar_action_cb callback;

} ext_toolbar_t;

typedef enum
{
    EXT_TOOLBAR_UPDATE_VALUE,
    EXT_TOOLBAR_UPDATE_DATA,
    EXT_TOOLBAR_UPDATE_DATABYINDEX,
    EXT_TOOLBAR_UPDATE_DATA_ADD,
    EXT_TOOLBAR_UPDATE_DATA_REMOVE,
    EXT_TOOLBAR_SET_ACTIVE
} ext_toolbar_update_type_t;

typedef struct _ext_toolbar_update_t
{
    ext_toolbar_update_type_t type;
    gboolean silent;
    gpointer user_data;
    gpointer data_index;
} ext_toolbar_update_t;

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

/* Sets a parent menu for the user menu.
 *
 * This will set a parent menu, which allows this menu to be filtered underneath
 * the given menu as a submenu. If the parent menu does not exist, the main menu
 * will be used
 *
 * @param menu the menu for which to add the entry
 * @param parentmenu a valid menu name for the parent menu
 */
WS_DLL_PUBLIC ext_menu_t * ext_menubar_set_parentmenu(
        ext_menu_t * menu, const gchar * parentmenu);

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

/* Registers a toolbar.
 *
 * This will register a new toolbar, which can contain various gui elements
 *
 * @param toolbar_label the entry label (the displayed name) for the toolbar item
 */
WS_DLL_PUBLIC ext_toolbar_t * ext_toolbar_register_toolbar(const gchar * toolbar_label);

/* Removes a toolbar from the system.
 *
 * This will remove the provided toolbar from the application
 *
 * @param toolbar the toolbar to be removed
 */
WS_DLL_PUBLIC void ext_toolbar_unregister_toolbar(ext_toolbar_t * toolbar);

/* Removes a toolbar from the system by providing the name of the toolbar.
 *
 * This will remove the provided toolbar from the application
 *
 * @param toolbar_name the name of the toolbar to be removed
 */
WS_DLL_PUBLIC void ext_toolbar_unregister_toolbar_by_name(const gchar * toolbar_name);

/* Registers a new toolbar entry.
 *
 * This registers a new toolbar entry, which will have the given name, and
 * call the provided callback on activation
 *
 * The callback will be fired on different events, depending on the item type
 * and the implementation of the item type in a GUI element. The following types should
 * behave as following
 *
 *  * EXT_TOOLBAR_STRING - Every change of the content fires the callback
 *  * EXT_TOOLBAR_BOOLEAN - Every change of the value fires the callback
 *  * EXT_TOOLBAR_BUTTON - if the button is pressed, the callback fires
 *  * EXT_TOOLBAR_SELECTION - every time the selection changes the callback fires
 *
 * @param parent_bar the parent toolbar for this entry
 * @param name the entry name (the internal used one) for the item
 * @param label the entry label (the displayed name) for the item
 * @param defvalue the default value for the toolbar element
 * @param tooltip a tooltip to be displayed on mouse-over
 * @param capture_only entry is only active, if capture is active
 * @param callback the action which will be invoked after click on the item
 * @param value_list a non-null list of values, if the item type is EXT_TOOLBAR_SELECTOR
 * @param valid_regex a validation regular expression for EXT_TOOLBAR_STRING
 *
 * @return a reference to the newly created toolbar entry
 */
WS_DLL_PUBLIC ext_toolbar_t * ext_toolbar_add_entry(
        ext_toolbar_t * parent_bar,
        ext_toolbar_item_t type,
        const gchar *label,
        const gchar *defvalue,
        const gchar *tooltip,
        gboolean capture_only,
        GList * value_list,
        gboolean is_required,
        const gchar * valid_regex,
        ext_toolbar_action_cb callback,
        gpointer user_data);

WS_DLL_PUBLIC GList * ext_toolbar_add_val(GList * entries, gchar * value, gchar * display, gboolean is_default);

WS_DLL_PUBLIC void ext_toolbar_register_update_cb(ext_toolbar_t * entry, ext_toolbar_action_cb callback, gpointer item_data);

/* Updates the entry values
 *
 * Update the values for the entry, it is up to the implemented widget, to interpret the
 * given character values
 *
 * @param entry the entry to be updated
 * @param data the data for the entry
 * @param silent the update for the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_value(ext_toolbar_t * entry, gpointer data, gboolean silent);

/* Updates the entry data
 *
 * Update the data for the entry, it is up to the implemented widget, to interpret the given character data
 *
 * @param entry the entry to be updated
 * @param data the data for the entry
 * @param silent the update for the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data(ext_toolbar_t * entry, gpointer data, gboolean silent);

/* Updates the entry data by index
 *
 * This is used to update a single entry of a selector list, by giving it's value and a new display
 * entry
 *
 * @param entry the toolbar item to be updated
 * @param data the display data for the entry
 * @param idx the value for the entry to be updated
 * @param silent the update for the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data_by_index(ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent);

/* Adds the entry data by index
 *
 * This is used to add a single entry to a selector list, by giving it's new value and a new display
 * entry. If the value already exists, the selector may choose to ignore the command
 *
 * @param entry the toolbar item to be updated
 * @param data the display data for the entry to be added
 * @param idx the value for the entry to be added
 * @param silent the adding of the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data_add_entry(ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent);

/* Removes an entry data by index
 *
 * This is used to remove a single entry to a selector list, by giving it's value and a display
 * entry. If the value already exists, the selector may choose to ignore the command. Both value
 * and display must be given, as it is not established, how the entry is found in the selector list
 *
 * @param entry the toolbar item to be updated
 * @param data the display data for the entry to be removed
 * @param idx the value for the entry to be removed
 * @param silent the removal of the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data_remove_entry(ext_toolbar_t * entry, gpointer data, gpointer idx, gboolean silent);

/* Search for and return if found an entry from the toolbar with the given label */
WS_DLL_PUBLIC ext_toolbar_t * ext_toolbar_entry_by_label(const ext_toolbar_t * toolbar, const gchar * label);

/* Set the ui element for the given enry to the status */
WS_DLL_PUBLIC void ext_toolbar_update_data_set_active(ext_toolbar_t * entry, gboolean status);

/*
 * Structure definition for the plugin_if_get_ws_info function
 */

typedef struct _ws_info_t
{
    gboolean ws_info_supported;                 /* false if no libpcap */
    file_state cf_state;                        /* Current state of capture file */
    gchar *cf_filename;                         /* Name of capture file */
    guint32 cf_count;                           /* Total number of frames */
    guint32 cf_framenr;                         /**< Currently displayed frame number */
    gboolean frame_passed_dfilter;              /**< true = display, false = no display */
} ws_info_t;


/*
 * Enumeration of possible actions, which are registered in GUI interfaces
 */
typedef enum
{
    /* Applies a given string as filter */
    PLUGIN_IF_FILTER_ACTION_APPLY,

    /* Prepares the given string as filter */
    PLUGIN_IF_FILTER_ACTION_PREPARE,

    /* Saves a preference entry */
    PLUGIN_IF_PREFERENCE_SAVE,

    /* Jumps to the provided frame number */
    PLUGIN_IF_GOTO_FRAME,

    /* Gets status information about the currently loaded capture file */
    PLUGIN_IF_GET_WS_INFO,

    /* Gets information from frame_data for current packet */
    PLUGIN_IF_GET_FRAME_DATA,

    /* Gets information from capture_file */
    PLUGIN_IF_GET_CAPTURE_FILE,

    /* Remove toolbar */
    PLUGIN_IF_REMOVE_TOOLBAR

} plugin_if_callback_t;


typedef void (*plugin_if_gui_cb)(GHashTable * data_set);

WS_DLL_PUBLIC void plugin_if_register_gui_cb(plugin_if_callback_t actionType, plugin_if_gui_cb callback);

/* Applies the given filter string as display filter */
WS_DLL_PUBLIC void plugin_if_apply_filter(const char * filter_string, gboolean force);

/* Saves the given preference to the main preference storage */
WS_DLL_PUBLIC void plugin_if_save_preference(const char * pref_module, const char * pref_key, const char * pref_value);

/* Jumps to the given frame number */
WS_DLL_PUBLIC void plugin_if_goto_frame(guint32 framenr);

/* Takes a snapshot of status information from Wireshark */
WS_DLL_PUBLIC void plugin_if_get_ws_info(ws_info_t ** ws_info);

typedef void* (*plugin_if_frame_data_cb)(frame_data*, void*);
/* Gets frame_data for current packet, data are extracted by extract_cb */
WS_DLL_PUBLIC void* plugin_if_get_frame_data(plugin_if_frame_data_cb extract_cb, void *user_data);

typedef void* (*plugin_if_capture_file_cb)(capture_file*, void*);
/* Gets capture_file, data are extracted by extract_cb */
WS_DLL_PUBLIC void* plugin_if_get_capture_file(plugin_if_capture_file_cb extract_cb, void* user_data);

/* Private Method for retrieving the menubar entries
 *
 * Is only to be used by the UI interfaces to retrieve the menu entries
 */
WS_DLL_PUBLIC GList * ext_menubar_get_entries(void);

/* Private Method for retrieving the toolbar entries
 *
 * Is only to be used by the UI interfaces to retrieve the toolbar entries
 */
WS_DLL_PUBLIC GList * ext_toolbar_get_entries(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EPAN_PLUGIN_IF_H */

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
