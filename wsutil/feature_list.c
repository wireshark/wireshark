/* feature_list.c
 * Routines for gathering and handling lists of present/absent features
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>

#include "config.h"

#include <wsutil/feature_list.h>

void
with_feature(feature_list l, const char *fmt, ...)
{
    va_list arg;
    GString *msg = g_string_new("+");
    va_start(arg, fmt);
    g_string_append_vprintf(msg, fmt, arg);
    va_end(arg);
    /* Strip "version from the string" */
    g_string_replace(msg, " version", "", 0);
    g_string_replace(msg, " based on", "", 0);
    *l = g_list_prepend(*l, g_string_free(msg, FALSE));
}

void
without_feature(feature_list l, const char *fmt, ...)
{
    va_list arg;
    GString *msg = g_string_new("-");
    va_start(arg, fmt);
    g_string_append_vprintf(msg, fmt, arg);
    va_end(arg);
    *l = g_list_prepend(*l, g_string_free(msg, FALSE));
}

static int
feature_sort_alpha(const void *a, const void *b)
{
    return g_ascii_strcasecmp((char *)a + 1, (char *)b + 1);
}

void
sort_features(feature_list l)
{
    *l = g_list_sort(*l, feature_sort_alpha);
}

void
separate_features(feature_list l, feature_list with_list, feature_list without_list)
{
    GList *iter;
    gchar *data;
    for (iter = *l; iter != NULL; iter = iter->next) {
        data = (gchar *)iter->data;
        if (data[0] == '+')
            *with_list = g_list_prepend(*with_list, g_strdup(data));
        else
            *without_list = g_list_prepend(*without_list, g_strdup(data));
    }
    *with_list = g_list_reverse(*with_list);
    *without_list = g_list_reverse(*without_list);
}

void
free_features(feature_list l)
{
    g_list_free_full(*l, g_free);
    *l = NULL;
}
