/* make-dissectors.c
 * Tool to build the dissector registration arrays.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <wsutil/glib-compat.h>

#define ARRAY_RESERVED_SIZE     2048

GRegex *protos_regex, *handoffs_regex;

static int
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

static void
scan_file(const char *file, GPtrArray *protos, GPtrArray *handoffs)
{
    char *contents;

    if (!g_file_get_contents(file, &contents, NULL, NULL))
        return;
    scan_matches(protos_regex, contents, protos);
    scan_matches(handoffs_regex, contents, handoffs);
    g_free(contents);
}

static void
scan_list(const char *list, GPtrArray *protos, GPtrArray *handoffs)
{
    char *contents, *arg;

    if (!g_file_get_contents(list, &contents, NULL, NULL))
        return;
    for (arg = strtok(contents, " \n"); arg != NULL; arg = strtok(NULL, " \n")) {
        scan_file(arg, protos, handoffs);
    }
    g_free(contents);
}

int main(int argc, char **argv)
{
    GPtrArray *protos = NULL, *handoffs = NULL;
    GError *err = NULL;
    guint i;
    FILE *out;

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

    for (int arg = 2; arg < argc; arg++) {
        if (argv[arg][0] == '@') {
            scan_list(&argv[arg][1], protos, handoffs);
        }
        else {
            scan_file(argv[arg], protos, handoffs);
        }
    }

    if (protos->len == 0) {
        fprintf(stderr, "No protocol registrations found.\n");
        exit(1);
    }

    out = fopen(argv[1], "w");
    if (out == NULL) {
        fprintf(stderr, "Error opening file: %s: %s\n", argv[1], strerror(errno));
        exit(1);
    }

    g_ptr_array_sort(protos, compare_symbols);
    g_ptr_array_sort(handoffs, compare_symbols);

    fprintf(out,
           "/*\n"
           " * Do not modify this file. Changes will be overwritten.\n"
           " *\n"
           " * Generated automatically by the \"dissectors.c\" target using\n"
           " * \"make-dissectors\".\n"
           " */\n"
           "\n"
           "#include <ws_symbol_export.h>\n"
           "#include <dissectors.h>\n"
           "\n");

    fprintf(out,
           "const gulong dissector_reg_proto_count = %d;\n"
           "const gulong dissector_reg_handoff_count = %d;\n"
           "\n",
            protos->len, handoffs->len);

    for (i = 0; i < protos->len; i++) {
        fprintf(out, "void %s(void);\n", (char *)protos->pdata[i]);
    }
    fprintf(out,
           "\n"
           "dissector_reg_t dissector_reg_proto[] = {\n");
    for (i = 0; i < protos->len; i++) {
        fprintf(out, "    { \"%s\", %s },\n", (char *)protos->pdata[i], (char *)protos->pdata[i]);
    }
    fprintf(out,
           "    { NULL, NULL }\n"
           "};\n"
           "\n");

    for (i = 0; i < handoffs->len; i++) {
        fprintf(out, "void %s(void);\n", (char *)handoffs->pdata[i]);
    }
    fprintf(out,
           "\n"
           "dissector_reg_t dissector_reg_handoff[] = {\n");
    for (i = 0; i < handoffs->len; i++) {
        fprintf(out, "    { \"%s\", %s },\n", (char *)handoffs->pdata[i], (char *)handoffs->pdata[i]);
    }
    fprintf(out,
           "    { NULL, NULL }\n"
           "};\n");

    fclose(out);

    printf("Found %u registrations and %u handoffs.\n", protos->len, handoffs->len);

    g_regex_unref(protos_regex);
    g_regex_unref(handoffs_regex);

    g_ptr_array_free(protos, TRUE);
    g_ptr_array_free(handoffs, TRUE);
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
