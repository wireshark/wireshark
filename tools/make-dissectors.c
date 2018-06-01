/* make-dissectors.c
 * Tool to build the dissector registration arrays.
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

#define ARRAY_RESERVED_SIZE     2048
#define STRING_RESERVED_SIZE    (300 * 1024)


int main(int argc, char **argv)
{
    GRegex *protos_regex, *handoffs_regex;
    GPtrArray *protos = NULL, *handoffs = NULL;
    struct symbol_item items[2];
    GError *err = NULL;
    guint i;
    GString *s;
    const char *outfile;
    guint count_protos, count_handoffs;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <outfile> <infiles...>\n", argv[0]);
        exit(1);
    }

    protos = g_ptr_array_new_full(ARRAY_RESERVED_SIZE, g_free);
    handoffs = g_ptr_array_new_full(ARRAY_RESERVED_SIZE, g_free);

    protos_regex = g_regex_new("void\\s+(proto_register_[[:alnum:]_]+)\\s*\\(\\s*void\\s*\\)\\s*{",
                                    G_REGEX_OPTIMIZE, G_REGEX_MATCH_NOTEMPTY, &err);
    if (err) {
        fprintf(stderr, "GRegex: %s\n", err->message);
        exit(1);
    }
    handoffs_regex = g_regex_new("void\\s+(proto_reg_handoff_[[:alnum:]_]+)\\s*\\(\\s*void\\s*\\)\\s*{",
                                    G_REGEX_OPTIMIZE, G_REGEX_MATCH_NOTEMPTY, &err);
    if (err) {
        fprintf(stderr, "GRegex: %s\n", err->message);
        exit(1);
    }

    items[0].regex = protos_regex;
    items[0].ptr_array = protos;
    items[1].regex = handoffs_regex;
    items[1].ptr_array = handoffs;

    outfile = argv[1];
    for (int arg = 2; arg < argc; arg++) {
        if (argv[arg][0] == '@') {
            scan_list(&argv[arg][1], items, G_N_ELEMENTS(items));
        }
        else {
            scan_file(argv[arg], items, G_N_ELEMENTS(items));
        }
    }

    if (protos->len == 0) {
        fprintf(stderr, "No protocol registrations found.\n");
        exit(1);
    }

    g_ptr_array_sort(protos, compare_symbols);
    g_ptr_array_sort(handoffs, compare_symbols);

    s = g_string_sized_new(STRING_RESERVED_SIZE);

    g_string_append(s,
            "/*\n"
            " * Do not modify this file. Changes will be overwritten.\n"
            " *\n"
            " * Generated automatically using \"make-dissectors\".\n"
            " */\n"
            "\n"
            "#include <dissectors.h>\n"
            "\n");

    g_string_append_printf(s,
            "const gulong dissector_reg_proto_count = %d;\n"
            "const gulong dissector_reg_handoff_count = %d;\n"
            "\n",
            protos->len, handoffs->len);

    for (i = 0; i < protos->len; i++) {
        g_string_append_printf(s,
            "void %s(void);\n",
            (char *)protos->pdata[i]);
    }
    g_string_append(s,
            "\n"
            "dissector_reg_t dissector_reg_proto[] = {\n");
    for (i = 0; i < protos->len; i++) {
        g_string_append_printf(s,
            "    { \"%s\", %s },\n",
            (char *)protos->pdata[i], (char *)protos->pdata[i]);
    }
    g_string_append(s,
            "    { NULL, NULL }\n"
            "};\n"
            "\n");

    for (i = 0; i < handoffs->len; i++) {
        g_string_append_printf(s,
            "void %s(void);\n",
            (char *)handoffs->pdata[i]);
    }
    g_string_append(s,
            "\n"
            "dissector_reg_t dissector_reg_handoff[] = {\n");
    for (i = 0; i < handoffs->len; i++) {
        g_string_append_printf(s,
            "    { \"%s\", %s },\n",
            (char *)handoffs->pdata[i], (char *)handoffs->pdata[i]);
    }
    g_string_append(s,
            "    { NULL, NULL }\n"
            "};\n");

    if (!g_file_set_contents(outfile, s->str, s->len, &err)) {
        fprintf(stderr, "%s: %s\n", outfile, err->message);
        exit(1);
    }

    count_protos = protos->len;
    count_handoffs = handoffs->len;

    g_string_free(s, TRUE);

    g_regex_unref(protos_regex);
    g_regex_unref(handoffs_regex);

    g_ptr_array_free(protos, TRUE);
    g_ptr_array_free(handoffs, TRUE);

    printf("Found %u registrations and %u handoffs.\n",
                count_protos, count_handoffs);

    return 0;
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
