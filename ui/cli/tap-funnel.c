/*
 *  tap-funnel.c
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

#include "config.h"


#include <epan/funnel.h>
#include <stdio.h>

#include "ws_attributes.h"

#include <wsutil/wslog.h>

void register_tap_listener_funnel(void);

struct _funnel_text_window_t {
    char *title;
    GString *text;
};

static GPtrArray *text_windows;

static funnel_text_window_t *new_text_window(funnel_ops_id_t *ops_id _U_, const char *title) {
    funnel_text_window_t *tw = g_new(funnel_text_window_t, 1);
    tw->title = g_strdup(title);
    tw->text = g_string_new("");

    if (!text_windows)
        text_windows = g_ptr_array_new();

    g_ptr_array_add(text_windows, tw);

    return tw;
}

static void text_window_clear(funnel_text_window_t *tw) {
    g_string_free(tw->text, TRUE);
    tw->text = g_string_new("");
}

static void text_window_append(funnel_text_window_t *tw, const char *text ) {
    g_string_append(tw->text, text);
}

static void text_window_set_text(funnel_text_window_t *tw, const char *text) {
    g_string_free(tw->text, TRUE);
    tw->text = g_string_new(text);
}

static void text_window_prepend(funnel_text_window_t *tw, const char *text) {
    g_string_prepend(tw->text, text);
}

static const char *text_window_get_text(funnel_text_window_t *tw) {
    return tw->text->str;
}


static const funnel_ops_t funnel_ops = {
    NULL,
    new_text_window,
    text_window_set_text,
    text_window_append,
    text_window_prepend,
    text_window_clear,
    text_window_get_text,
    NULL,
    NULL,
    NULL,
    NULL,
    /*...,*/
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


void initialize_funnel_ops(void) {
    funnel_set_funnel_ops(&funnel_ops);
}


void funnel_dump_all_text_windows(void) {
    unsigned i;

    if (!text_windows) return;

    for ( i = 0 ; i < text_windows->len; i++) {
        funnel_text_window_t *tw = (funnel_text_window_t *)g_ptr_array_index(text_windows, i);
        printf("\n========================== %s "
               "==========================\n%s\n", tw->title, tw->text->str);

        g_ptr_array_remove_index(text_windows, i);
        g_free(tw->title);
        g_string_free(tw->text, TRUE);
        g_free(tw);
    }
}

#if 0

GHashTable *menus;
typedef struct _menu_cb_t {
    void (*callback)(void *);
    void *callback_data;
} menu_cb_t;


static void  init_funnel_cmd(const char *opt_arg, void *data ) {
    char **args = g_strsplit(opt_arg, ",", 0);
    char **arg;
    menu_cb_t *mcb = data;

    for (arg = args; *arg ; arg++) {
        g_strstrip(*arg);
    }

    if (mcb->callback) {
        mcb->callback(mcb->callback_data);
    }

}

static void register_menu_cb(const char *name,
                             register_stat_group_t group _U_,
                             void (*callback)(void *),
                             void *callback_data,
                             bool retap _U_) {
    menu_cb_t* mcb = g_new(menu_cb_t, 1);
    stat_tap_ui ui_info;

    mcb->callback = callback;
    mcb->callback_data = callback_data;

    if (!menus)
        menus = g_hash_table_new(g_str_hash, g_str_equal);

    g_hash_table_insert(menus, g_strdup(name), mcb);

    ui_info.group = REGISTER_STAT_GROUP_GENERIC;
    ui_info.title = NULL;
    ui_info.cli_string = name;
    ui_info.tap_init_cb = init_funnel_cmd;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, mcb);
}

void initialize_funnel_ops(void) {
    funnel_set_funnel_ops(&funnel_ops);
}

#endif
void
register_tap_listener_funnel(void)
{
#if 0
    /* #if 0 at least since Revision Rev 17396 */
    funnel_register_all_menus(register_menu_cb);
#endif
}
