/* make-lib.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>

struct symbol_item {
    GRegex *regex;
    GPtrArray *ptr_array;
};

/* Compares symbols using strcmp() */
int compare_symbols(gconstpointer a, gconstpointer b);

/* Scan a C source file for symbols */
void scan_file(const char *file, struct symbol_item *items, size_t items_len);

/* Takes a text file containing a list of C source files on which to call scan_file() */
void scan_list(const char *file, struct symbol_item *items, size_t items_len);


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
