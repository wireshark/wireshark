/** @file
 *
 * EPAN's GUI mini-API
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <wireshark.h>
#include <epan/stat_groups.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _funnel_ops_id_t funnel_ops_id_t; /* Opaque pointer to ops instance */
typedef struct _funnel_text_window_t funnel_text_window_t ;

typedef void (*text_win_close_cb_t)(void*);

typedef void (*funnel_dlg_cb_t)(char** user_input, void* data);
typedef void (*funnel_dlg_cb_data_free_t)(void* data);

typedef bool (*funnel_bt_cb_t)(funnel_text_window_t* tw, void* data);

typedef void (* funnel_menu_callback)(void *);
typedef void (* funnel_menu_callback_data_free)(void *);

/**
 * @brief Represents a button attached to a funnel text window, bundling its callback, data, and cleanup functions.
 */
typedef struct _funnel_bt_t {
    funnel_text_window_t* tw;            /**< The text window this button is associated with. */
    funnel_bt_cb_t        func;          /**< Callback invoked when the button is clicked. */
    void*                 data;          /**< User-supplied data passed to the button callback. */
    void (*free_fcn)(void*);             /**< Function used to free the button callback closure itself. */
    void (*free_data_fcn)(void*);        /**< Function used to free the user-supplied data pointer. */
} funnel_bt_t;


/** @brief Opaque progress dialog handle. */
struct progdlg;


/**
 * @brief Vtable of GUI operations provided to the Lua funnel API, abstracting all UI interactions behind function pointers.
 */
typedef struct _funnel_ops_t {
    funnel_ops_id_t* ops_id; /**< Opaque identifier for the GUI instance that owns these operations. */

    /**
     * @brief Creates and displays a new text window with the given label.
     * @param ops_id The GUI instance identifier.
     * @param label  Title label for the new text window.
     * @return Pointer to the newly created funnel_text_window_t.
     */
    funnel_text_window_t* (*new_text_window)(funnel_ops_id_t *ops_id, const char* label);

    /**
     * @brief Replaces the entire contents of a text window with the given text.
     * @param win  The target text window.
     * @param text The replacement text.
     */
    void (*set_text)(funnel_text_window_t* win, const char* text);

    /**
     * @brief Appends text to the end of a text window's contents.
     * @param win  The target text window.
     * @param text The text to append.
     */
    void (*append_text)(funnel_text_window_t* win, const char* text);

    /**
     * @brief Prepends text to the beginning of a text window's contents.
     * @param win  The target text window.
     * @param text The text to prepend.
     */
    void (*prepend_text)(funnel_text_window_t* win, const char* text);

    /**
     * @brief Clears all text content from a text window.
     * @param win The target text window.
     */
    void (*clear_text)(funnel_text_window_t* win);

    /**
     * @brief Retrieves the current text content of a text window.
     * @param win The target text window.
     * @return Pointer to the current text content string; caller must not free it.
     */
    const char* (*get_text)(funnel_text_window_t* win);

    /**
     * @brief Registers a callback to be invoked when a text window is closed.
     * @param win  The target text window.
     * @param cb   The close callback function.
     * @param data User-supplied data passed to the callback.
     */
    void (*set_close_cb)(funnel_text_window_t* win, text_win_close_cb_t cb, void* data);

    /**
     * @brief Sets whether a text window's content is user-editable.
     * @param win      The target text window.
     * @param editable True to allow editing, false to make the window read-only.
     */
    void (*set_editable)(funnel_text_window_t* win, bool editable);

    /**
     * @brief Destroys a text window and releases its associated resources.
     * @param win The text window to destroy.
     */
    void (*destroy_text_window)(funnel_text_window_t* win);

    /**
     * @brief Adds a button to a text window.
     * @param win   The target text window.
     * @param cb    The button descriptor containing callback and data.
     * @param label The label displayed on the button.
     */
    void (*add_button)(funnel_text_window_t* win, funnel_bt_t* cb, const char* label);

    /**
     * @brief Opens a modal input dialog with a set of labeled fields.
     * @param ops_id           The GUI instance identifier.
     * @param title            Title of the dialog window.
     * @param field_names      NULL-terminated array of field label strings.
     * @param field_values     NULL-terminated array of default values for each field.
     * @param dlg_cb           Callback invoked when the user confirms the dialog.
     * @param data             User-supplied data passed to the dialog callback.
     * @param dlg_cb_data_free Function used to free the user-supplied data when the dialog is dismissed.
     */
    void (*new_dialog)(funnel_ops_id_t *ops_id,
                       const char* title,
                       const char** field_names,
                       const char** field_values,
                       funnel_dlg_cb_t dlg_cb,
                       void* data,
                       funnel_dlg_cb_data_free_t dlg_cb_data_free);

    /**
     * @brief Closes all open funnel dialogs.
     */
    void (*close_dialogs)(void);

    /**
     * @brief Triggers a retap of all packets, re-running tap listeners without full redissection.
     * @param ops_id The GUI instance identifier.
     */
    void (*retap_packets)(funnel_ops_id_t *ops_id);

    /**
     * @brief Copies the contents of a GString to the system clipboard.
     * @param str The string to copy to the clipboard.
     */
    void (*copy_to_clipboard)(GString *str);

    /**
     * @brief Retrieves the currently applied display filter string.
     * @param ops_id The GUI instance identifier.
     * @return The current display filter string; caller must not free it.
     */
    const char* (*get_filter)(funnel_ops_id_t *ops_id);

    /**
     * @brief Applies a new display filter string to the packet list.
     * @param ops_id The GUI instance identifier.
     * @param filter The display filter string to apply.
     */
    void (*set_filter)(funnel_ops_id_t *ops_id, const char* filter);

    /**
     * @brief Retrieves the display filter assigned to a color filter slot.
     * @param filt_nr Zero-based index of the color filter slot.
     * @return The filter string for the given slot; caller must free it.
     */
    char* (*get_color_filter_slot)(uint8_t filt_nr);

    /**
     * @brief Assigns a display filter string to a color filter slot.
     * @param filt_nr Zero-based index of the color filter slot.
     * @param filter  The display filter string to assign.
     */
    void (*set_color_filter_slot)(uint8_t filt_nr, const char* filter);

    /**
     * @brief Opens a capture file, optionally applying a display filter.
     * @param ops_id The GUI instance identifier.
     * @param fname  Path to the capture file to open.
     * @param filter Optional display filter to apply after opening, or NULL.
     * @param error  On failure, set to a newly allocated error message string; caller must free it.
     * @return True on success, false on failure.
     */
    bool (*open_file)(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char** error);

    /**
     * @brief Reloads the current capture file from disk.
     * @param ops_id The GUI instance identifier.
     */
    void (*reload_packets)(funnel_ops_id_t *ops_id);

    /**
     * @brief Forces a full redissection of all packets in the current capture.
     * @param ops_id The GUI instance identifier.
     */
    void (*redissect_packets)(funnel_ops_id_t *ops_id);

    /**
     * @brief Reloads all Lua plugins and redissects packets.
     * @param ops_id The GUI instance identifier.
     */
    void (*reload_lua_plugins)(funnel_ops_id_t *ops_id);

    /**
     * @brief Applies the currently set display filter to the packet list.
     * @param ops_id The GUI instance identifier.
     */
    void (*apply_filter)(funnel_ops_id_t *ops_id);

    /**
     * @brief Opens a URL in the system's default web browser.
     * @param url The URL string to open.
     * @return True if the browser was successfully launched, false otherwise.
     */
    bool (*browser_open_url)(const char *url);

    /**
     * @brief Opens a local data file in the system's default application.
     * @param filename Path to the file to open.
     */
    void (*browser_open_data_file)(const char *filename);

    /**
     * @brief Creates and displays a progress dialog.
     * @param ops_id           The GUI instance identifier.
     * @param label            Title label for the progress dialog.
     * @param task             Description of the current task shown in the dialog.
     * @param terminate_is_stop True if termination should be labeled "Stop" rather than "Cancel".
     * @param stop_flag        Pointer to a flag set to true when the user requests cancellation.
     * @return Pointer to the newly created progress dialog handle.
     */
    struct progdlg* (*new_progress_window)(funnel_ops_id_t *ops_id, const char* label, const char* task, bool terminate_is_stop, bool *stop_flag);

    /**
     * @brief Updates the progress bar and task description of a progress dialog.
     * @param dlg  The progress dialog to update.
     * @param pr   Progress value in the range [0.0, 1.0].
     * @param task Updated description of the current task.
     */
    void (*update_progress)(struct progdlg* dlg, float pr, const char* task);

    /**
     * @brief Destroys a progress dialog and releases its resources.
     * @param dlg The progress dialog to destroy.
     */
    void (*destroy_progress_window)(struct progdlg* dlg);
} funnel_ops_t;

/**
 * @brief Get the funnel operations.
 *
 * @return Pointer to the funnel operations structure.
 */
WS_DLL_PUBLIC const funnel_ops_t* funnel_get_funnel_ops(void);

/**
 * @brief Checks if a menu is registered.
 *
 * @return true if the menu is registered, false otherwise.
 */
WS_DLL_PUBLIC bool funnel_menu_registered(void);

/**
 * @brief Registers a menu callback.
 *
 * @param name The name of the menu to register.
 * @param group The group to which the menu belongs.
 * @param callback The callback function to be called when the menu is invoked.
 * @param callback_data User data to be passed to the callback function.
 * @param callback_data_free Function to free the user data when it's no longer needed.
 * @param retap Whether to retap packets after registering the menu.
 */
WS_DLL_PUBLIC void funnel_register_menu(const char *name,
                                 register_stat_group_t group,
                                 funnel_menu_callback callback,
                                 void *callback_data,
                                 funnel_menu_callback_data_free callback_data_free,
                                 bool retap);

/**
 * @brief Deregisters a menu callback.
 *
 * @param callback The callback function to be deregistered.
 */
void funnel_deregister_menus(funnel_menu_callback callback);

typedef void (*funnel_registration_cb_t)(const char *name,
                                         register_stat_group_t group,
                                         funnel_menu_callback callback,
                                         void *callback_data,
                                         bool retap);
typedef void (*funnel_deregistration_cb_t)(funnel_menu_callback callback);

/**
 * @brief Reloads the menus by deregistering and registering them again using provided callbacks.
 *
 * @param d_cb Callback function to deregister menu items.
 * @param r_cb Callback function to register new menu items.
 */
WS_DLL_PUBLIC void funnel_reload_menus(funnel_deregistration_cb_t d_cb,
                                       funnel_registration_cb_t r_cb);

/**
 * @brief Cleans up resources used by the funnel subsystem.
 *
 * This function is responsible for freeing all allocated resources and
 * cleaning up any state held by the funnel subsystem before it is
 * terminated.
 */
WS_DLL_PUBLIC void funnel_cleanup(void);

/**
 * Signature of function that can be called from a custom packet menu entry
 */
typedef void (* funnel_packet_menu_callback)(void *, GPtrArray*);

/**
 * Signature of callback function to register packet menu entries
 */
typedef void (*funnel_registration_packet_cb_t)(const char *name,
                                         const char *required_fields,
                                         funnel_packet_menu_callback callback,
                                         void *callback_data,
                                         bool retap);

/**
 * @brief Entry point for Wireshark GUI to obtain all registered packet menus
 *
 * @param r_cb function which will be called to register each packet menu entry
 */
WS_DLL_PUBLIC void funnel_register_all_packet_menus(funnel_registration_packet_cb_t r_cb);

/**
 * @brief Entry point for Lua code to register a packet menu
 *
 * @param name packet menu item's name
 * @param required_fields fields required to be present for the packet menu to be displayed
 * @param callback function called when the menu item is invoked. The function must take one argument and return nothing.
 * @param callback_data Lua state for the callback function
 * @param retap whether or not to rescan all packets
 */
WS_DLL_PUBLIC void funnel_register_packet_menu(const char *name,
                                 const char *required_fields,
                                 funnel_packet_menu_callback callback,
                                 void *callback_data,
                                 bool retap);

/**
 * @brief Returns whether the packet menus have been modified since they were last registered
 *
 * @return true if the packet menus were modified since the last registration
 */
WS_DLL_PUBLIC bool funnel_packet_menus_modified(void);

/*
 * The functions below allow registering a funnel "console". A console is just a GUI
 * dialog that has an input text widget, an output text widget, and for each user
 * generated input it calls a callback to generate the corresponding output.
 * Very simple... each console type has a name and an entry in the Tools menu to invoke it.
 * Mainly used to present a Lua console to allow inspecting Lua internals and run Lua
 * code using the embedded interpreter.
 */

/**
 * Signature of function that can be called to evaluate code.
  * Returns zero on success, -1 if precompilation failed, positive for runtime errors.
 */
typedef int (*funnel_console_eval_cb_t)(const char *console_input,
                                            char **error_ptr,
                                            char **error_hint,
                                            void *callback_data);

/**
 * Signature of function that can be called to install a logger.
 */
typedef void (*funnel_console_open_cb_t)(void (*print_func)(const char *, void *), void *print_data, void *callback_data);

/**
 * Signature of function that can be called to remove logger.
 */
typedef void (*funnel_console_close_cb_t)(void *callback_data);

/**
 * Signature of function that can be called to free user data.
 */
typedef void (*funnel_console_data_free_cb_t)(void *callback_data);

/**
 * Entry point for Lua code to register a console menu
 */
WS_DLL_PUBLIC void funnel_register_console_menu(const char *name,
                                funnel_console_eval_cb_t eval_cb,
                                funnel_console_open_cb_t open_cb,
                                funnel_console_close_cb_t close_cb,
                                void *callback_data,
                                funnel_console_data_free_cb_t free_data);

/**
 * Signature of callback function to register console menu entries
 */
typedef void (*funnel_registration_console_cb_t)(const char *name,
                                funnel_console_eval_cb_t eval_cb,
                                funnel_console_open_cb_t open_cb,
                                funnel_console_close_cb_t close_cb,
                                void *callback_data);

/**
* @brief Initialize the funnel operations.  This is done outside of
* epan_init() because the funnel operations depend on GUI code.
*
* @param r_cb function which will be called to register each console menu entry
*/
WS_DLL_PUBLIC void funnel_ops_init(const funnel_ops_t* ops, funnel_registration_cb_t r_cb, funnel_registration_console_cb_t rconsole_cb);

#ifdef __cplusplus
}
#endif /* __cplusplus */
