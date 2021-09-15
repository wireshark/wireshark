/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <glib.h>
#include <wsutil/utf8_entities.h>

#include "str_util.h"


void test_format_size(void)
{
    char *str;

    str = format_size(10000, format_size_unit_bytes);
    g_assert_cmpstr(str, ==, "10 kB");
    g_free(str);

    str = format_size(100000, format_size_unit_bytes|format_size_prefix_iec);
    g_assert_cmpstr(str, ==, "97 KiB");
    g_free(str);

    str = format_size(20971520, format_size_unit_bits|format_size_prefix_iec);
    g_assert_cmpstr(str, ==, "20 Mib");
    g_free(str);
}

#include "to_str.h"

void test_bytes_to_str(void)
{
    char *str;

    const guint8 buf[] = { 1, 2, 3};

    str = bytes_to_str(NULL, buf, sizeof(buf));
    g_assert_cmpstr(str, ==, "010203");
    g_free(str);
}

void test_bytes_to_str_punct(void)
{
    char *str;

    const guint8 buf[] = { 1, 2, 3};

    str = bytes_to_str_punct(NULL, buf, sizeof(buf), ':');
    g_assert_cmpstr(str, ==, "01:02:03");
    g_free(str);
}

void test_bytes_to_string_trunc1(void)
{
    char *str;

    const guint8 buf[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA
    };
    const char *expect =
        "112233445566778899aa"
        "112233445566778899aa"
        "112233445566778899aa"
        "112233445566" UTF8_HORIZONTAL_ELLIPSIS;

    str = bytes_to_str(NULL, buf, sizeof(buf));
    g_assert_cmpstr(str, ==, expect);
    g_free(str);
}

void test_bytes_to_string_punct_trunc1(void)
{
    char *str;

    const guint8 buf[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA
    };
    const char *expect =
        "11:22:33:44:55:66:77:88:99:aa:"
        "11:22:33:44:55:66:77:88:99:aa:"
        "11:22:33:44:" UTF8_HORIZONTAL_ELLIPSIS;

    str = bytes_to_str_punct(NULL, buf, sizeof(buf), ':');
    g_assert_cmpstr(str, ==, expect);
    g_free(str);
}

static char to_str_back_buf[32];
#define BACK_PTR (&to_str_back_buf[31]) /* pointer to NUL string terminator */

void test_oct_to_str_back(void)
{
    char *str;

    str = oct_to_str_back(BACK_PTR, 958769886);
    g_assert_cmpstr(str,  ==, "07111325336");

    str = oct_to_str_back(BACK_PTR, 781499127);
    g_assert_cmpstr(str,  ==, "05645135367");

    str = oct_to_str_back(BACK_PTR, 1177329882);
    g_assert_cmpstr(str, ==, "010613120332");
}

void test_oct64_to_str_back(void)
{
    char *str;

    str = oct64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(13873797580070999420));
    g_assert_cmpstr(str, ==, "01402115026217563452574");

    str = oct64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(7072159458371400691));
    g_assert_cmpstr(str, ==, "0610452670726711271763");

    str = oct64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(12453513102400590374));
    g_assert_cmpstr(str, ==, "01263236102754220511046");
}

void test_hex_to_str_back_len(void)
{
    char *str;

    str = hex_to_str_back_len(BACK_PTR, 2481, 8);
    g_assert_cmpstr(str, ==, "0x000009b1");

    str = hex_to_str_back_len(BACK_PTR, 2457, 8);
    g_assert_cmpstr(str, ==, "0x00000999");

    str = hex_to_str_back_len(BACK_PTR, 16230, 8);
    g_assert_cmpstr(str, ==, "0x00003f66");
}

void test_hex64_to_str_back_len(void)
{
    char *str;

    str = hex64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(1), 16);
    g_assert_cmpstr(str, ==, "0x0000000000000001");

    str = hex64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(4294967295), 16);
    g_assert_cmpstr(str, ==, "0x00000000ffffffff");

    str = hex64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(18446744073709551615), 16);
    g_assert_cmpstr(str, ==, "0xffffffffffffffff");
}

void test_uint_to_str_back(void)
{
    char *str;

    str = uint_to_str_back(BACK_PTR, 873735883);
    g_assert_cmpstr(str, ==, "873735883");

    str = uint_to_str_back(BACK_PTR, 1801148094);
    g_assert_cmpstr(str, ==, "1801148094");

    str = uint_to_str_back(BACK_PTR, 181787997);
    g_assert_cmpstr(str, ==, "181787997");
}

void test_uint64_to_str_back(void)
{
    char *str;

    str = uint64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(585143757104211265));
    g_assert_cmpstr(str, ==, "585143757104211265");

    str = uint64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(7191580247919484847));
    g_assert_cmpstr(str, ==, "7191580247919484847");

    str = uint64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(95778573911934485));
    g_assert_cmpstr(str, ==, "95778573911934485");
}

void test_uint_to_str_back_len(void)
{
    char *str;

    str = uint_to_str_back_len(BACK_PTR, 26630, 8);
    g_assert_cmpstr(str, ==, "00026630");

    str = uint_to_str_back_len(BACK_PTR, 25313, 8);
    g_assert_cmpstr(str, ==, "00025313");

    str = uint_to_str_back_len(BACK_PTR, 18750000, 8);
    g_assert_cmpstr(str, ==, "18750000");
}

void test_uint64_to_str_back_len(void)
{
    char *str;

    str = uint64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(1), 16);
    g_assert_cmpstr(str, ==, "0000000000000001");

    str = uint64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(4294967295), 16);
    g_assert_cmpstr(str, ==, "0000004294967295");

    str = uint64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(18446744073709551615), 16);
    g_assert_cmpstr(str, ==, "18446744073709551615");
}

void test_int_to_str_back(void)
{
    char *str;

    str = int_to_str_back(BACK_PTR, -763689611);
    g_assert_cmpstr(str, ==, "-763689611");

    str = int_to_str_back(BACK_PTR, -296015954);
    g_assert_cmpstr(str, ==, "-296015954");

    str = int_to_str_back(BACK_PTR, 898901469);
    g_assert_cmpstr(str, ==, "898901469");
}

void test_int64_to_str_back(void)
{
    char *str;

    str = int64_to_str_back(BACK_PTR, G_GINT64_CONSTANT(-9223372036854775807));
    g_assert_cmpstr(str, ==, "-9223372036854775807");

    str = int64_to_str_back(BACK_PTR, G_GINT64_CONSTANT(1));
    g_assert_cmpstr(str, ==, "1");

    str = int64_to_str_back(BACK_PTR, G_GINT64_CONSTANT(9223372036854775807));
    g_assert_cmpstr(str, ==, "9223372036854775807");
}

int main(int argc, char **argv)
{
    int ret;

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/str_util/format_size", test_format_size);

    g_test_add_func("/to_str/bytes_to_str", test_bytes_to_str);
    g_test_add_func("/to_str/bytes_to_str_punct", test_bytes_to_str_punct);
    g_test_add_func("/to_str/bytes_to_str_trunc1", test_bytes_to_string_trunc1);
    g_test_add_func("/to_str/bytes_to_str_punct_trunc1", test_bytes_to_string_punct_trunc1);
    g_test_add_func("/to_str/oct_to_str_back", test_oct_to_str_back);
    g_test_add_func("/to_str/oct64_to_str_back", test_oct64_to_str_back);
    g_test_add_func("/to_str/hex_to_str_back_len", test_hex_to_str_back_len);
    g_test_add_func("/to_str/hex64_to_str_back_len", test_hex64_to_str_back_len);
    g_test_add_func("/to_str/uint_to_str_back", test_uint_to_str_back);
    g_test_add_func("/to_str/uint64_to_str_back", test_uint64_to_str_back);
    g_test_add_func("/to_str/uint_to_str_back_len", test_uint_to_str_back_len);
    g_test_add_func("/to_str/uint64_to_str_back_len", test_uint64_to_str_back_len);
    g_test_add_func("/to_str/int_to_str_back", test_int_to_str_back);
    g_test_add_func("/to_str/int64_to_str_back", test_int64_to_str_back);

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
