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
#ifndef __FUNNEL_H__
#define __FUNNEL_H__

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

typedef struct _funnel_bt_t {
	funnel_text_window_t* tw;
	funnel_bt_cb_t func;
	void* data;
	void (*free_fcn)(void*);
	void (*free_data_fcn)(void*);
} funnel_bt_t;

struct progdlg;

typedef struct _funnel_ops_t {
    funnel_ops_id_t *ops_id;
    funnel_text_window_t* (*new_text_window)(funnel_ops_id_t *ops_id, const char* label);
    void (*set_text)(funnel_text_window_t*  win, const char* text);
    void (*append_text)(funnel_text_window_t*  win, const char* text);
    void (*prepend_text)(funnel_text_window_t*  win, const char* text);
    void (*clear_text)(funnel_text_window_t*  win);
    const char* (*get_text)(funnel_text_window_t*  win);
    void (*set_close_cb)(funnel_text_window_t*  win, text_win_close_cb_t cb, void* data);
    void (*set_editable)(funnel_text_window_t*  win, bool editable);
    void (*destroy_text_window)(funnel_text_window_t*  win);
    void (*add_button)(funnel_text_window_t*  win, funnel_bt_t* cb, const char* label);

    void (*new_dialog)(funnel_ops_id_t *ops_id,
                    const char* title,
                    const char** field_names,
                    const char** field_values,
                    funnel_dlg_cb_t dlg_cb,
                    void* data,
                    funnel_dlg_cb_data_free_t dlg_cb_data_free);

    void (*close_dialogs)(void);

    void (*retap_packets)(funnel_ops_id_t *ops_id);
    void (*copy_to_clipboard)(GString *str);

    const char * (*get_filter)(funnel_ops_id_t *ops_id);
    void (*set_filter)(funnel_ops_id_t *ops_id, const char* filter);
    char * (*get_color_filter_slot)(uint8_t filt_nr);
    void (*set_color_filter_slot)(uint8_t filt_nr, const char* filter);
    bool (*open_file)(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char** error);
    void (*reload_packets)(funnel_ops_id_t *ops_id);
    void (*redissect_packets)(funnel_ops_id_t *ops_id);
    void (*reload_lua_plugins)(funnel_ops_id_t *ops_id);
    void (*apply_filter)(funnel_ops_id_t *ops_id);

    bool (*browser_open_url)(const char *url);
    void (*browser_open_data_file)(const char *filename);

    struct progdlg* (*new_progress_window)(funnel_ops_id_t *ops_id, const char* label, const char* task, bool terminate_is_stop, bool *stop_flag);
    void (*update_progress)(struct progdlg*, float pr, const char* task);
    void (*destroy_progress_window)(struct progdlg*);
} funnel_ops_t;

WS_DLL_PUBLIC const funnel_ops_t* funnel_get_funnel_ops(void);
WS_DLL_PUBLIC void funnel_set_funnel_ops(const funnel_ops_t*);

WS_DLL_PUBLIC void funnel_register_menu(const char *name,
                                 register_stat_group_t group,
                                 funnel_menu_callback callback,
                                 void *callback_data,
                                 funnel_menu_callback_data_free callback_data_free,
                                 bool retap);
void funnel_deregister_menus(void (*callback)(void *));

typedef void (*funnel_registration_cb_t)(const char *name,
                                         register_stat_group_t group,
                                         funnel_menu_callback callback,
                                         void *callback_data,
                                         bool retap);
typedef void (*funnel_deregistration_cb_t)(funnel_menu_callback callback);

WS_DLL_PUBLIC void funnel_register_all_menus(funnel_registration_cb_t r_cb);
WS_DLL_PUBLIC void funnel_reload_menus(funnel_deregistration_cb_t d_cb,
                                       funnel_registration_cb_t r_cb);
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
 * Entry point for Wireshark GUI to obtain all registered packet menus
 *
 * @param r_cb function which will be called to register each packet menu entry
 */
WS_DLL_PUBLIC void funnel_register_all_packet_menus(funnel_registration_packet_cb_t r_cb);

/**
 * Entry point for Lua code to register a packet menu
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
 * Returns whether the packet menus have been modified since they were last registered
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
 * Entry point for Wireshark GUI to obtain all registered console menus
 *
 * @param r_cb function which will be called to register each console menu entry
 */
WS_DLL_PUBLIC void funnel_register_all_console_menus(funnel_registration_console_cb_t r_cb);

extern void initialize_funnel_ops(void);

extern void funnel_dump_all_text_windows(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FUNNEL_H__ */
