/*
 *  funnel.h
 *
 * EPAN's GUI mini-API
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
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
#ifndef __FUNNEL_H__
#define __FUNNEL_H__

#include <glib.h>
#include <epan/stat_groups.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _funnel_ops_id_t funnel_ops_id_t; /* Opaque pointer to ops instance */
typedef struct _funnel_progress_window_t funnel_progress_window_t ;
typedef struct _funnel_text_window_t funnel_text_window_t ;
typedef struct _funnel_tree_window_t funnel_tree_window_t ; /* XXX Unused? */
typedef struct _funnel_node_t funnel_node_t ; /* XXX Unused? */

typedef void (*text_win_close_cb_t)(void*);

typedef void (*funnel_dlg_cb_t)(gchar** user_input, void* data);

typedef gboolean (*funnel_bt_cb_t)(funnel_text_window_t* tw, void* data);

typedef void (* funnel_menu_callback)(gpointer);

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
    funnel_text_window_t* (*new_text_window)(const char* label);
    void (*set_text)(funnel_text_window_t*  win, const char* text);
    void (*append_text)(funnel_text_window_t*  win, const char* text);
    void (*prepend_text)(funnel_text_window_t*  win, const char* text);
    void (*clear_text)(funnel_text_window_t*  win);
    const char* (*get_text)(funnel_text_window_t*  win);
    void (*set_close_cb)(funnel_text_window_t*  win, text_win_close_cb_t cb, void* data);
    void (*set_editable)(funnel_text_window_t*  win, gboolean editable);
    void (*destroy_text_window)(funnel_text_window_t*  win);
    void (*add_button)(funnel_text_window_t*  win, funnel_bt_t* cb, const char* label);

    void (*new_dialog)(const gchar* title,
		       const gchar** fieldnames,
		       funnel_dlg_cb_t dlg_cb,
		       void* data);

    void (*close_dialogs)(void);

    void (*logger)(const gchar *log_domain,
                   GLogLevelFlags log_level,
                   const gchar *message,
                   gpointer user_data);


    void (*retap_packets)(funnel_ops_id_t *ops_id);
    void (*copy_to_clipboard)(GString *str);

    const gchar * (*get_filter)(funnel_ops_id_t *ops_id);
    void (*set_filter)(funnel_ops_id_t *ops_id, const char* filter);
    void (*set_color_filter_slot)(guint8 flit_nr, const gchar* filter);
    gboolean (*open_file)(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char** error);
    void (*reload_packets)(funnel_ops_id_t *ops_id);
    void (*reload_lua_plugins)(funnel_ops_id_t *ops_id);
    void (*apply_filter)(funnel_ops_id_t *ops_id);

    gboolean (*browser_open_url)(const gchar *url);
    void (*browser_open_data_file)(const gchar *filename);

    struct progdlg* (*new_progress_window)(funnel_ops_id_t *ops_id, const gchar* label, const gchar* task, gboolean terminate_is_stop, gboolean *stop_flag);
    void (*update_progress)(struct progdlg*, float pr, const gchar* task);
    void (*destroy_progress_window)(struct progdlg*);
} funnel_ops_t;

WS_DLL_PUBLIC const funnel_ops_t* funnel_get_funnel_ops(void);
WS_DLL_PUBLIC void funnel_set_funnel_ops(const funnel_ops_t*);

WS_DLL_PUBLIC void funnel_register_menu(const char *name,
                                 register_stat_group_t group,
                                 funnel_menu_callback callback,
                                 gpointer callback_data,
                                 gboolean retap);
void funnel_deregister_menus(void (*callback)(gpointer));

typedef void (*funnel_registration_cb_t)(const char *name,
                                         register_stat_group_t group,
                                         funnel_menu_callback callback,
                                         gpointer callback_data,
                                         gboolean retap);
typedef void (*funnel_deregistration_cb_t)(funnel_menu_callback callback);

WS_DLL_PUBLIC void funnel_register_all_menus(funnel_registration_cb_t r_cb);
WS_DLL_PUBLIC void funnel_reload_menus(funnel_deregistration_cb_t d_cb,
                                       funnel_registration_cb_t r_cb);

extern void initialize_funnel_ops(void);

extern void funnel_dump_all_text_windows(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FUNNEL_H__ */
