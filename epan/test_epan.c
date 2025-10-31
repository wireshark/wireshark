/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "strutil.h"
#include <wsutil/utf8_entities.h>

/*
 * FIXME: LABEL_LENGTH includes the nul byte terminator.
 * This is confusing but matches ITEM_LABEL_LENGTH.
 */
#define LABEL_LENGTH 8

void test_label_strcat(void)
{
    char label[LABEL_LENGTH];
    const char *src;
    size_t pos;

    src = "ABCD";
    pos = 0;
    pos = ws_label_strcpy(label, sizeof(label), pos, src, 0);
    g_assert_cmpstr(label, ==, "ABCD");
    g_assert_cmpuint(pos, ==, 4);

    src = "EFGH";
    pos = ws_label_strcpy(label, sizeof(label), pos, src, 0);
    g_assert_cmpstr(label, ==, "ABCDEFG");
    g_assert_cmpuint(pos, ==, 8);

    src = "IJKL";
    pos = 7;
    pos = ws_label_strcpy(label, sizeof(label), pos, src, 0);
    g_assert_cmpstr(label, ==, "ABCDEFG");
    g_assert_cmpuint(pos, ==, 11);

    /* UTF-8 multibyte does not fit, do not truncate. */
    src = "ABCDEF"UTF8_MIDDLE_DOT;
    pos = 0;
    pos = ws_label_strcpy(label, sizeof(label), pos, src, 0);
    g_assert_cmpstr(label, ==, "ABCDEF");
    g_assert_cmpuint(pos, ==, 8); /* Tried to write 8 bytes. */
}

void test_label_strcat_escape_whitespace(void)
{
    char label[128];
    const char *src, *dst;
    size_t pos;

    src = "ABCD\n\t\f\r\aE"UTF8_MIDDLE_DOT"Z";
    dst = "ABCD\\n\\t\\f\\r\\aE"UTF8_MIDDLE_DOT"Z";
    pos = ws_label_strcpy(label, sizeof(label), 0, src, 0);
    g_assert_cmpstr(label, ==, dst);
    g_assert_cmpuint(pos, ==, strlen(dst));
}

void test_label_escape_control(void)
{
    char label[128];
    const char *src, *dst;
    size_t pos;

    src = "ABCD \x04\x17\xC2\x80 EFG \xC2\x90 HIJ \xC2\x9F Z";
    dst = "ABCD \\x04\\x17\\u0080 EFG \\u0090 HIJ \\u009F Z";
    pos = ws_label_strcpy(label, sizeof(label), 0, src, 0);
    g_assert_cmpstr(label, ==, dst);
    g_assert_cmpuint(pos, ==, strlen(dst));
}

int main(int argc, char **argv)
{
    int ret;

    /* Set the program name. */
    g_set_prgname("test_proto");

    ws_log_init(NULL, "Testing Debug Console");

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/label/strcat", test_label_strcat);
    g_test_add_func("/label/escape_whitespace", test_label_strcat_escape_whitespace);
    g_test_add_func("/label/escape_control", test_label_escape_control);

    ret = g_test_run();

    return ret;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
