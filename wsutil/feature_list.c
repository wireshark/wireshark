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
free_features(feature_list l)
{
    g_list_free_full(*l, g_free);
    *l = NULL;
}
