/* make-lib.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "make-lib.h"


#ifdef _WIN32
  #define SEP   "\r\n"
#else
  #define SEP   "\n"
#endif


int
compare_symbols(gconstpointer a, gconstpointer b)
{
    return g_strcmp0(*(const char **)a, *(const char **)b);
}

static void
scan_matches(GRegex *regex, const char *string, GPtrArray *dst)
{
    GMatchInfo *match_info;
    char *match;

    g_regex_match(regex, string, G_REGEX_MATCH_NOTEMPTY, &match_info);
    while (g_match_info_matches(match_info)) {
        match = g_match_info_fetch(match_info, 1);
        g_ptr_array_add(dst, match);
        g_match_info_next(match_info, NULL);
    }
    g_match_info_free(match_info);
}

void
scan_file(const char *file, struct symbol_item *items, size_t items_len)
{
    char *contents;
    GError *err = NULL;
    size_t i;

    if (!g_file_get_contents(file, &contents, NULL, &err)) {
        fprintf(stderr, "%s: %s\n", file, err->message);
        exit(1);
    }
    for (i = 0; i < items_len; i++) {
        scan_matches(items[i].regex, contents, items[i].ptr_array);
    }
    g_free(contents);
}

void
scan_list(const char *file, struct symbol_item *items, size_t items_len)
{
    char *contents, *arg;
    GError *err = NULL;

    if (!g_file_get_contents(file, &contents, NULL, &err)) {
        fprintf(stderr, "%s: %s\n", file, err->message);
        exit(1);
    }
    for (arg = strtok(contents, SEP); arg != NULL; arg = strtok(NULL, SEP)) {
        scan_file(arg, items, items_len);
    }
    g_free(contents);
}


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
