/* make-taps.c
 * Tool to build the tap registration arrays.
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

#define ARRAY_RESERVED_SIZE     128
#define STRING_RESERVED_SIZE    (8 * 1024)


int main(int argc, char **argv)
{
    GRegex *taps_regex;
    GPtrArray *taps = NULL;
    struct symbol_item items[1];
    GError *err = NULL;
    guint i;
    GString *s;
    const char *outfile;
    guint count_taps;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <outfile> <infiles...>\n", argv[0]);
        exit(1);
    }

    taps = g_ptr_array_new_full(ARRAY_RESERVED_SIZE, g_free);

    taps_regex = g_regex_new("void\\s+(register_tap_listener_[[:alnum:]_]+)\\s*\\(\\s*void\\s*\\)\\s*{",
                                    G_REGEX_OPTIMIZE, G_REGEX_MATCH_NOTEMPTY, &err);
    if (err) {
        fprintf(stderr, "GRegex: %s\n", err->message);
        exit(1);
    }

    items[0].regex = taps_regex;
    items[0].ptr_array = taps;

    outfile = argv[1];
    for (int arg = 2; arg < argc; arg++) {
         scan_file(argv[arg], items, G_N_ELEMENTS(items));
    }

    if (taps->len == 0) {
        fprintf(stderr, "No tap registrations found.\n");
        exit(1);
    }

    g_ptr_array_sort(taps, compare_symbols);

    s = g_string_sized_new(STRING_RESERVED_SIZE);

    g_string_append(s,
            "/*\n"
            " * Do not modify this file. Changes will be overwritten.\n"
            " *\n"
            " * Generated automatically using \"make-taps\".\n"
            " */\n"
            "\n"
            "#include \"ui/taps.h\"\n"
            "\n");

    g_string_append_printf(s,
            "const gulong tap_reg_listener_count = %d;\n"
            "\n",
            taps->len);

    for (i = 0; i < taps->len; i++) {
        g_string_append_printf(s,
            "void %s(void);\n",
            (char *)taps->pdata[i]);
    }
    g_string_append(s,
            "\n"
            "tap_reg_t tap_reg_listener[] = {\n");
    for (i = 0; i < taps->len; i++) {
        g_string_append_printf(s,
            "    { \"%s\", %s },\n",
            (char *)taps->pdata[i], (char *)taps->pdata[i]);
    }
    g_string_append(s,
            "    { NULL, NULL }\n"
            "};\n"
            "\n");

    if (!g_file_set_contents(outfile, s->str, s->len, &err)) {
        fprintf(stderr, "%s: %s\n", outfile, err->message);
        exit(1);
    }

    count_taps = taps->len;

    g_string_free(s, TRUE);

    g_regex_unref(taps_regex);

    g_ptr_array_free(taps, TRUE);

    printf("Found %u registrations.\n", count_taps);
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
