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
    funnel_ops_init(&funnel_ops, NULL, NULL);
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
