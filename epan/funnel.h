/*
 *  funnel.h
 *
 * EPAN's GUI mini-API
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#ifndef _FUNNEL_H
#define _FUNNEL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include "../stat_menu.h"

typedef struct _funnel_text_window_t funnel_text_window_t ;
typedef struct _funnel_tree_window_t funnel_tree_window_t ;
typedef struct _funnel_node_t funnel_node_t ;

typedef void (*text_win_close_cb_t)(void*);

typedef void (*funnel_dlg_cb_t)(gchar** user_input, void* data);

typedef struct _funnel_ops_t {
    funnel_text_window_t* (*new_text_window)(const gchar* label);
    void (*set_text)(funnel_text_window_t*  win, const gchar* text);
    void (*append_text)(funnel_text_window_t*  win, const gchar* text);
    void (*prepend_text)(funnel_text_window_t*  win, const gchar* text);
    void (*clear_text)(funnel_text_window_t*  win);
    const gchar* (*get_text)(funnel_text_window_t*  win);
    void (*set_close_cb)(funnel_text_window_t*  win, text_win_close_cb_t cb, void* data);
    void (*destroy_text_window)(funnel_text_window_t*  win);
#if 0
    funnel_node_t* (*new_tree_window)(const gchar* title, gchar** columns);
    funnel_node_t* (*add_node)(funnel_node_t* node, gchar** values);
    void  (*remove_node)(funnel_node_t* node);
    void  (*set_cell)(funnel_node_t* node, gchar* column, const gchar* text);

    void (*set_filter)(const gchar* filter_string);

#endif

    void (*new_dialog)(const gchar* title,
                                   const gchar** fieldnames,
                                   funnel_dlg_cb_t dlg_cb,
                                   void* data);
    
    void (*logger)(const gchar *log_domain,
                   GLogLevelFlags log_level,
                   const gchar *message,
                   gpointer user_data);
	
	void (*retap_packets)(void);
} funnel_ops_t;


extern const funnel_ops_t* funnel_get_funnel_ops(void);
extern void funnel_set_funnel_ops(const funnel_ops_t*);


extern void funnel_register_menu(const char *name,
                                 REGISTER_STAT_GROUP_E group,
                                 void (*callback)(gpointer),
                                 gpointer callback_data,
                                 gboolean retap);


typedef void (*funnel_registration_cb_t)(const char *name,
                                         REGISTER_STAT_GROUP_E group,
                                         void (*callback)(gpointer),
                                         gpointer callback_data,
                                         gboolean retap);

extern void funnel_register_all_menus(funnel_registration_cb_t r_cb);

extern void initialize_funnel_ops(void);

extern void funnel_dump_all_text_windows(void);

#endif
