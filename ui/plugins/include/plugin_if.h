/** @file
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
#include <epan/frame_data.h>
#include <epan/cfile.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Identifies the GUI toolkit hosting the menubar, passed to action callbacks.
 */
typedef enum
{
    EXT_MENUBAR_GTK_GUI, /**< Legacy GTK+ GUI host */
    EXT_MENUBAR_QT_GUI   /**< Qt GUI host */
} ext_menubar_gui_type;


/**
 * @brief Callback invoked when a menubar item is activated.
 *
 * @param gui_type   The GUI toolkit that triggered the action (see ::ext_menubar_gui_type).
 * @param gui_object Toolkit-specific widget or window object associated with the event.
 * @param user_data  Caller-supplied context pointer registered with the menu item.
 */
typedef void (*ext_menubar_action_cb)(ext_menubar_gui_type gui_type, void *gui_object, void *user_data);


/**
 * @brief Classifies a node within the menubar entry tree.
 */
typedef enum
{
    EXT_MENUBAR_MENU,      /**< A submenu container that may hold child entries */
    EXT_MENUBAR_ITEM,      /**< A clickable action item */
    EXT_MENUBAR_SEPARATOR, /**< A visual separator between items */
    EXT_MENUBAR_URL        /**< An item that opens a URL in a browser */
} ext_menubar_entry_t;


typedef struct _ext_menubar_t ext_menubar_t;
typedef ext_menubar_t ext_menu_t; /**< Convenience alias — a menu is the root form of ::ext_menubar_t */


/**
 * @brief Represents a node in the plugin-registered menubar tree (menu, item, separator, or URL).
 */
struct _ext_menubar_t
{
    ext_menubar_entry_t  type;         /**< Node type: menu, item, separator, or URL */
    ext_menu_t          *parent;       /**< Parent menu node, or NULL if this is a top-level menu */
    int                  proto;        /**< Protocol ID this menu entry is associated with */
    GList               *children;     /**< Ordered list of child ::ext_menubar_t nodes (menus only) */
    unsigned             submenu_cnt;  /**< Number of direct submenu children */
    unsigned             item_cnt;     /**< Number of direct item/URL/separator children */

    char *name;       /**< Internal identifier name for this entry */
    char *label;      /**< Display label shown in the GUI menu */

    char *tooltip;    /**< Tooltip text shown on hover, or NULL */
    bool  is_plugin;  /**< True if this entry was registered by a plugin */
    void *user_data;  /**< Caller-supplied context pointer forwarded to @p callback */

    ext_menubar_action_cb callback;  /**< Action callback invoked when the item is activated, or NULL */

    char *parent_menu; /**< Name of the top-level menu under which this entry should appear */
};

/**
 * @brief Callback invoked when a toolbar item's value or button state changes.
 *
 * @param toolbar_item Handle to the toolbar widget that was activated.
 * @param item_data    Current value or state data for the toolbar item.
 * @param user_data    Caller-supplied context pointer registered with the item.
 */
typedef void (*ext_toolbar_action_cb)(void *toolbar_item, void *item_data, void *user_data);

/**
 * @brief Classifies a node within the toolbar entry tree.
 */
typedef enum
{
    EXT_TOOLBAR_BAR,  /**< A toolbar container that holds child items */
    EXT_TOOLBAR_ITEM  /**< An individual control item within a toolbar */
} ext_toolbar_entry_t;

/**
 * @brief Specifies the widget type for a toolbar control item.
 */
typedef enum
{
    EXT_TOOLBAR_BOOLEAN,  /**< A toggle / checkbox control */
    EXT_TOOLBAR_BUTTON,   /**< A momentary push-button */
    EXT_TOOLBAR_STRING,   /**< A free-form text-entry field */
    EXT_TOOLBAR_SELECTOR  /**< A drop-down selector with a fixed list of values */
} ext_toolbar_item_t;

/**
 * @brief A single selectable value entry for a selector-type toolbar item.
 */
typedef struct _ext_toolbar_value_t
{
    char *value;      /**< Machine-readable value string sent to the callback */
    char *display;    /**< Human-readable label shown in the selector widget */
    bool  is_default; /**< True if this entry should be selected by default */
} ext_toolbar_value_t;

/**
 * @brief Represents a node in the plugin-registered toolbar tree (bar or item).
 */
typedef struct _ext_toolbar_t
{
    ext_toolbar_entry_t type;        /**< Node type: toolbar bar or item */

    GList   *children;    /**< Ordered list of child ::ext_toolbar_t nodes (bar nodes only) */
    unsigned submenu_cnt; /**< Number of direct toolbar-bar children */
    unsigned item_cnt;    /**< Number of direct item children */

    char *name;      /**< Internal identifier name for this toolbar or item */
    char *defvalue;  /**< Default value string applied on initialisation */
    char *tooltip;   /**< Tooltip text shown on hover, or NULL */
    void *user_data; /**< Caller-supplied context pointer forwarded to @p callback */

    bool               is_required;   /**< True if a value must be provided before capture can start */
    bool               capture_only;  /**< True if this item is enabled during capture only */
    ext_toolbar_item_t item_type;     /**< Widget type for this item (see ::ext_toolbar_item_t) */

    GList *values; /**< Ordered list of ::ext_toolbar_value_t entries (selector items only) */
    char  *regex;  /**< Optional regular expression used to validate string input */

    ext_toolbar_action_cb callback; /**< Callback invoked when the item value or button state changes */
} ext_toolbar_t;

/**
 * @brief Specifies the kind of update operation to apply to a toolbar item.
 */
typedef enum
{
    EXT_TOOLBAR_UPDATE_VALUE,       /**< Replace the item's current value */
    EXT_TOOLBAR_UPDATE_DATA,        /**< Replace the item's full data set (e.g. selector list) */
    EXT_TOOLBAR_UPDATE_DATABYINDEX, /**< Update a single entry in the data set identified by index */
    EXT_TOOLBAR_UPDATE_DATA_ADD,    /**< Append a new entry to the item's data set */
    EXT_TOOLBAR_UPDATE_DATA_REMOVE, /**< Remove an entry from the item's data set */
    EXT_TOOLBAR_SET_ACTIVE          /**< Set the enabled/active state of the item */
} ext_toolbar_update_type_t;


/**
 * @brief Carries the parameters for a single toolbar item update operation.
 */
typedef struct _ext_toolbar_update_t
{
    ext_toolbar_update_type_t type;       /**< The kind of update to perform (see ::ext_toolbar_update_type_t) */
    bool                      silent;     /**< If true, suppress any UI notification or callback triggered by the update */
    void                     *user_data;  /**< New value or payload for the update operation */
    void                     *data_index; /**< Index identifying the target entry for index-based update operations */
} ext_toolbar_update_t;

/**
 * @brief Registers a new main menu.
 *
 * This will register a new main menu entry, underneath all other menu entries will
 * be sorted
 *
 * @param proto_id the proto item for the protocol this menu entry belongs too
 * @param menulabel the entry label (the displayed name) for the menu item
 * @param is_plugin must be set to true for plugin registration
 */
WS_DLL_PUBLIC ext_menu_t * ext_menubar_register_menu(
        int proto_id, const char * menulabel, bool is_plugin);

/**
 * @brief Sets a parent menu for the user menu.
 *
 * This will set a parent menu, which allows this menu to be filtered underneath
 * the given menu as a submenu. If the parent menu does not exist, the main menu
 * will be used
 *
 * @param menu the menu for which to add the entry
 * @param parentmenu a valid menu name for the parent menu
 */
WS_DLL_PUBLIC ext_menu_t * ext_menubar_set_parentmenu(
        ext_menu_t * menu, const char * parentmenu);

/**
 * @brief Registers a new main menu.
 *
 * This will register a new sub menu entry, underneath the parent menu
 *
 * @param parent the parent menu for this submenu
 * @param menulabel the entry label (the displayed name) for the menu item
 */
WS_DLL_PUBLIC ext_menu_t * ext_menubar_add_submenu(
        ext_menu_t * parent, const char *menulabel);

/**
 * @brief Registers a new menubar entry.

 *
 * This registers a new menubar entry, which will have the given name, and
 * call the provided callback on activation
 *
 * @param parent_menu the parent menu for this entry
 * @param label the entry label (the displayed name) for the menu item
 * @param tooltip a tooltip to be displayed on mouse-over
 * @param callback the action which will be invoked after click on the menu item
 * @param user_data a user data pointer
 */
WS_DLL_PUBLIC void ext_menubar_add_entry(
        ext_menu_t * parent_menu,
        const char *label,
        const char *tooltip,
        ext_menubar_action_cb callback,
        void *user_data);

/**
 * @brief Registers a new separator entry.
 *
 * @note This will not work using the legacy GTK interface, due to
 * restrictions on how separators are handled in the menu
 *
 * @param parent_menu the parent menu for this entry
 */
WS_DLL_PUBLIC void ext_menubar_add_separator(ext_menu_t *parent_menu);

/**
 * @brief Registers a entry for a website call
 *
 * This registers a new menubar entry, which will call the given website, using
 * the predefined webbrowser
 *
 * @param parent the parent menu for this entry
 * @param label the entry label (the displayed name) for the menu item
 * @param tooltip a tooltip to be displayed on mouse-over
 * @param url the url for the website
 */
WS_DLL_PUBLIC void ext_menubar_add_website(ext_menu_t * parent, const char *label,
        const char *tooltip, const char *url);

/**
 * @brief Registers a toolbar.
 *
 * This will register a new toolbar, which can contain various gui elements
 *
 * @param toolbar_label the entry label (the displayed name) for the toolbar item
 */
WS_DLL_PUBLIC ext_toolbar_t * ext_toolbar_register_toolbar(const char * toolbar_label);

/**
 * @brief Removes a toolbar from the system.
 *
 * This will remove the provided toolbar from the application
 *
 * @param toolbar the toolbar to be removed
 */
WS_DLL_PUBLIC void ext_toolbar_unregister_toolbar(ext_toolbar_t * toolbar);

/**
 * @brief Removes a toolbar from the system by providing the name of the toolbar.
 *
 * This will remove the provided toolbar from the application
 *
 * @param toolbar_name the name of the toolbar to be removed
 */
WS_DLL_PUBLIC void ext_toolbar_unregister_toolbar_by_name(const char * toolbar_name);

/**
 * @brief Registers a new toolbar entry.
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
 * @param type type of the toolbar item
 * @param label the entry label (the displayed name) for the item
 * @param defvalue the default value for the toolbar element
 * @param tooltip a tooltip to be displayed on mouse-over
 * @param capture_only entry is only active, if capture is active
 * @param value_list a non-null list of values, if the item type is EXT_TOOLBAR_SELECTOR
 * @param is_required if the item is required to be shown in the toolbar, if false, the user can choose to hide the item
 * @param valid_regex a validation regular expression for EXT_TOOLBAR_STRING
 * @param callback the action which will be invoked after click on the item
 * @param user_data a user data pointer
 * @return a reference to the newly created toolbar entry
 */
WS_DLL_PUBLIC ext_toolbar_t * ext_toolbar_add_entry(
        ext_toolbar_t * parent_bar,
        ext_toolbar_item_t type,
        const char *label,
        const char *defvalue,
        const char *tooltip,
        bool capture_only,
        GList * value_list,
        bool is_required,
        const char * valid_regex,
        ext_toolbar_action_cb callback,
        void *user_data);

/**
 * @brief Adds a new value entry to an existing toolbar.
 *
 * @param entries The list of existing toolbar entries.
 * @param value The value associated with the entry.
 * @param display The display text for the entry.
 * @param is_default Indicates if this entry should be set as default.
 * @return GList* The updated list of toolbar entries with the new value added.
 */
WS_DLL_PUBLIC GList * ext_toolbar_add_val(GList * entries, char * value, char * display, bool is_default);

/**
 * @brief Registers a callback for toolbar updates.
 *
 * This function allows you to register a callback that will be called whenever a toolbar entry is updated. The callback will receive the updated entry, the type of update, and any user data associated with the entry.
 *
 * @param entry The toolbar entry for which to register the update callback.
 * @param callback The callback function to be called when the toolbar entry is updated.
 * @param item_data User data to be passed to the callback function when it is called.
 */
WS_DLL_PUBLIC void ext_toolbar_register_update_cb(ext_toolbar_t * entry, ext_toolbar_action_cb callback, void *item_data);

/**
 * @brief Updates the entry values
 *
 * Update the values for the entry, it is up to the implemented widget, to interpret the
 * given character values
 *
 * @param entry the entry to be updated
 * @param data the data for the entry
 * @param silent the update for the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_value(ext_toolbar_t * entry, void *data, bool silent);

/**
 * @brief Updates the entry data
 *
 * Update the data for the entry, it is up to the implemented widget, to interpret the given character data
 *
 * @param entry the entry to be updated
 * @param data the data for the entry
 * @param silent the update for the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data(ext_toolbar_t * entry, void *data, bool silent);

/**
 * @brief Updates the entry data by index
 *
 * This is used to update a single entry of a selector list, by giving it's value and a new display
 * entry
 *
 * @param entry the toolbar item to be updated
 * @param data the display data for the entry
 * @param idx the value for the entry to be updated
 * @param silent the update for the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data_by_index(ext_toolbar_t * entry, void *data, void *idx, bool silent);

/**
 * @brief Adds the entry data by index
 *
 * This is used to add a single entry to a selector list, by giving it's new value and a new display
 * entry. If the value already exists, the selector may choose to ignore the command
 *
 * @param entry the toolbar item to be updated
 * @param data the display data for the entry to be added
 * @param idx the value for the entry to be added
 * @param silent the adding of the entry should not trigger additional actions
 */
WS_DLL_PUBLIC void ext_toolbar_update_data_add_entry(ext_toolbar_t * entry, void *data, void *idx, bool silent);

/**
 * @brief Removes an entry data by index
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
WS_DLL_PUBLIC void ext_toolbar_update_data_remove_entry(ext_toolbar_t * entry, void *data, void *idx, bool silent);

/**
 * @brief Searches for and returns an entry from the toolbar with the given label
 * @param toolbar The toolbar to search in
 * @param label The label of the entry to search for
 * @return The found entry or NULL if not found
 */
WS_DLL_PUBLIC ext_toolbar_t * ext_toolbar_entry_by_label(const ext_toolbar_t * toolbar, const char * label);

/**
 * @brief Sets the UI element for the given entry to the specified status
 * @param entry The toolbar entry to update
 * @param status The status to set
 */
WS_DLL_PUBLIC void ext_toolbar_update_data_set_active(ext_toolbar_t * entry, bool status);

/*
 * Structure definition for the plugin_if_get_ws_info function
 */

/**
 * @brief Snapshot of current Wireshark application state, passed to plugins via plugin_if_get_ws_info.
 */
typedef struct _ws_info_t
{
    bool ws_info_supported;          /**< False if no libpcap support is available; structure fields are invalid when false. */
    file_state cf_state;             /**< Current state of the open capture file (e.g., reading, ready, closed). */
    char *cf_filename;               /**< Path and name of the currently open capture file, or NULL if none. */
    uint32_t cf_count;               /**< Total number of frames in the capture file. */
    uint32_t cf_framenr;             /**< Frame number of the currently displayed frame. */
    bool frame_passed_dfilter;       /**< True if the current frame passes the active display filter; false if hidden. */
} ws_info_t;


/**
 * @brief Identifies a GUI action that a plugin can invoke through the plugin interface callback mechanism.
 */
typedef enum
{
    PLUGIN_IF_FILTER_ACTION_APPLY,   /**< Apply the provided display filter string immediately to the packet list */
    PLUGIN_IF_FILTER_ACTION_PREPARE, /**< Stage the provided display filter string in the filter bar without applying it */
    PLUGIN_IF_PREFERENCE_SAVE,       /**< Persist a preference key/value entry to the active profile */
    PLUGIN_IF_GOTO_FRAME,            /**< Scroll the packet list to the specified frame number */
    PLUGIN_IF_GET_WS_INFO,           /**< Retrieve status information about the currently loaded capture file */
    PLUGIN_IF_GET_FRAME_DATA,        /**< Retrieve ::frame_data fields for the currently selected packet */
    PLUGIN_IF_GET_CAPTURE_FILE,      /**< Retrieve the ::capture_file structure for the current capture */
    PLUGIN_IF_REMOVE_TOOLBAR         /**< Unregister and remove a previously added plugin toolbar from the GUI */
} plugin_if_callback_t;


/**
 * @brief Callback function type for GUI-related actions.
 *
 * This function type is used for callbacks that are registered to handle specific GUI-related actions in Wireshark. The callback will receive a GHashTable containing relevant data for the action being performed.
 *
 * @param data_set A GHashTable containing data relevant to the GUI action. The specific keys and values in the hash table will depend on the action type for which the callback is registered.
 */
typedef void (*plugin_if_gui_cb)(GHashTable * data_set);

/**
 * @brief Registers a callback function for GUI-related actions.
 *
 * @param actionType The type of action to register the callback for.
 * @param callback The callback function to be called when the action occurs.
 */
WS_DLL_PUBLIC void plugin_if_register_gui_cb(plugin_if_callback_t actionType, plugin_if_gui_cb callback);

/**
 * @brief Applies the given filter string as display filter
 * @param filter_string The filter string to apply
 * @param force Whether to force the filter application
 */
WS_DLL_PUBLIC void plugin_if_apply_filter(const char * filter_string, bool force);

/**
 * @brief Saves a preference to the main preference storage.
 *
 * @param pref_module The module name of the preference.
 * @param pref_key The key name of the preference.
 * @param pref_value The value to save for the preference.
 */
WS_DLL_PUBLIC void plugin_if_save_preference(const char * pref_module, const char * pref_key, const char * pref_value);

/**
 * @brief Jumps to the given frame number.
 * @param framenr The frame number to jump to.
 */
WS_DLL_PUBLIC void plugin_if_goto_frame(uint32_t framenr);

/**
 * @brief Takes a snapshot of status information from Wireshark.
 * @param ws_info Pointer to a ws_info_t structure to store the status information.
 */
WS_DLL_PUBLIC void plugin_if_get_ws_info(ws_info_t ** ws_info);

typedef void* (*plugin_if_frame_data_cb)(frame_data*, void*);

/**
 * @brief Gets frame_data for current packet, data are extracted by extract_cb.
 * @param extract_cb The callback function to extract frame data.
 * @param user_data User-defined data to pass to the callback function.
 * @return Pointer to the extracted frame data.
 */
WS_DLL_PUBLIC void* plugin_if_get_frame_data(plugin_if_frame_data_cb extract_cb, void *user_data);

typedef void* (*plugin_if_capture_file_cb)(capture_file*, void*);

/**
 * @brief Gets capture_file, data are extracted by extract_cb.
 * @param extract_cb The callback function to extract capture file data.
 * @param user_data User-defined data to pass to the callback function.
 * @return Pointer to the extracted capture file data.
 */
WS_DLL_PUBLIC void* plugin_if_get_capture_file(plugin_if_capture_file_cb extract_cb, void* user_data);

/**
 * @brief Private Method for retrieving the menubar entries
 *
 * Is only to be used by the UI interfaces to retrieve the menu entries
 * @return A list of menu entries.
 */
WS_DLL_PUBLIC GList * ext_menubar_get_entries(void);

/**
 * @brief Private Method for retrieving the toolbar entries
 *
 * Is only to be used by the UI interfaces to retrieve the toolbar entries
 * @return A list of toolbar entries.
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
