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

#include "inet_addr.h"

static void test_inet_pton4_test1(void)
{
    const char *str;
    bool ok;
    ws_in4_addr result, expect;

    str = "198.51.100.200";
    expect = g_htonl(3325256904);
    ok = ws_inet_pton4(str, &result);
    g_assert_true(ok);
    g_assert_cmpint(result, ==, expect);
}

static void test_inet_ntop4_test1(void)
{
    char result[WS_INET_ADDRSTRLEN];
    const char *expect, *ptr;
    ws_in4_addr addr;

    addr = g_htonl(3325256904);
    expect = "198.51.100.200";
    ptr = ws_inet_ntop4(&addr, result, sizeof(result));
    g_assert_true(ptr == result);
    g_assert_cmpstr(result, ==, expect);
}

struct in6_test {
    char str[WS_INET6_ADDRSTRLEN];
    ws_in6_addr addr;
};

static struct in6_test in6_test1 = {
    .str = "2001:db8:ffaa:ddbb:1199:2288:3377:1",
    .addr = { { 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xaa, 0xdd, 0xbb,
                0x11, 0x99, 0x22, 0x88, 0x33, 0x77, 0x00, 0x01 } }
};

static void test_inet_pton6_test1(void)
{
    bool ok;
    ws_in6_addr result;

    ok = ws_inet_pton6(in6_test1.str, &result);
    g_assert_true(ok);
    g_assert_cmpmem(&result, sizeof(result), &in6_test1.addr, sizeof(in6_test1.addr));
}

static void test_inet_ntop6_test1(void)
{
    char result[WS_INET6_ADDRSTRLEN];
    const char *ptr;

    ptr = ws_inet_ntop6(&in6_test1.addr, result, sizeof(result));
    g_assert_true(ptr == result);
    g_assert_cmpstr(result, ==, in6_test1.str);
}

#include "str_util.h"

static void test_format_size(void)
{
    char *str;

    str = format_size(10000, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_SI);
    g_assert_cmpstr(str, ==, "10 kB");
    g_free(str);

    str = format_size(100000, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_IEC);
    g_assert_cmpstr(str, ==, "97 KiB");
    g_free(str);

    str = format_size(20971520, FORMAT_SIZE_UNIT_BITS, FORMAT_SIZE_PREFIX_IEC);
    g_assert_cmpstr(str, ==, "20 Mib");
    g_free(str);
}

static void test_escape_string(void)
{
    char *buf;

    buf = ws_escape_string(NULL, "quoted \"\\\" backslash", true);
    g_assert_cmpstr(buf, ==, "\"quoted \\\"\\\\\\\" backslash\"");
    wmem_free(NULL, buf);

    buf = ws_escape_string(NULL, "whitespace \t \n \r \f \v", true);
    g_assert_cmpstr(buf, ==, "\"whitespace \\t \\n \\r \\f \\v""\"");
    wmem_free(NULL, buf);

    const char s1[] = { 'a', 'b', 'c', '\0', 'e', 'f', 'g'};
    buf = ws_escape_null(NULL, s1, sizeof(s1), true);
    g_assert_cmpstr(buf, ==, "\"abc\\0efg\"");
    wmem_free(NULL, buf);
}

static void test_strconcat(void)
{
    wmem_allocator_t   *allocator;
    char               *new_str;

    allocator = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);

    new_str = wmem_strconcat(allocator, "ABC", NULL);
    g_assert_cmpstr(new_str, ==, "ABC");

    new_str = wmem_strconcat(allocator, "ABC", "DEF", NULL);
    g_assert_cmpstr(new_str, ==, "ABCDEF");

    new_str = wmem_strconcat(allocator, "", "", "ABCDEF", "", "GH", NULL);
    g_assert_cmpstr(new_str, ==, "ABCDEFGH");

    wmem_destroy_allocator(allocator);
}

static void test_strsplit(void)
{
    wmem_allocator_t   *allocator;
    char              **split_str;

    allocator = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);

    split_str = wmem_strsplit(allocator, "A-C", "-", 2);
    g_assert_cmpstr(split_str[0], ==, "A");
    g_assert_cmpstr(split_str[1], ==, "C");
    g_assert_null(split_str[2]);

    split_str = wmem_strsplit(allocator, "A-C", "-", 0);
    g_assert_cmpstr(split_str[0], ==, "A");
    g_assert_cmpstr(split_str[1], ==, "C");
    g_assert_null(split_str[2]);

    split_str = wmem_strsplit(allocator, "--aslkf-asio--asfj-as--", "-", 10);
    g_assert_cmpstr(split_str[0], ==, "");
    g_assert_cmpstr(split_str[1], ==, "");
    g_assert_cmpstr(split_str[2], ==, "aslkf");
    g_assert_cmpstr(split_str[3], ==, "asio");
    g_assert_cmpstr(split_str[4], ==, "");
    g_assert_cmpstr(split_str[5], ==, "asfj");
    g_assert_cmpstr(split_str[6], ==, "as");
    g_assert_cmpstr(split_str[7], ==, "");
    g_assert_cmpstr(split_str[8], ==, "");
    g_assert_null(split_str[9]);

    split_str = wmem_strsplit(allocator, "--aslkf-asio--asfj-as--", "-", 5);
    g_assert_cmpstr(split_str[0], ==, "");
    g_assert_cmpstr(split_str[1], ==, "");
    g_assert_cmpstr(split_str[2], ==, "aslkf");
    g_assert_cmpstr(split_str[3], ==, "asio");
    g_assert_cmpstr(split_str[4], ==, "-asfj-as--");
    g_assert_null(split_str[5]);

    split_str = wmem_strsplit(allocator, "", "-", -1);
    g_assert_null(split_str[0]);

    wmem_destroy_allocator(allocator);
}

static void test_str_ascii(void)
{
    wmem_allocator_t   *allocator;
    const char         *orig_str;
    char               *new_str;

    allocator = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);

    orig_str = "TeStAsCiIsTrDoWn";
    new_str = wmem_ascii_strdown(allocator, orig_str, -1);
    g_assert_cmpstr(new_str, ==, "testasciistrdown");

    wmem_destroy_allocator(allocator);
}

#include "to_str.h"

static void test_word_to_hex(void)
{
    static char buf[32];
    char *str;     /* String is not NULL terminated. */

    str = guint8_to_hex(buf, 0x34);
    g_assert_true(str == buf + 2);
    g_assert_cmpint(str[-1], ==, '4');
    g_assert_cmpint(str[-2], ==, '3');

    str = word_to_hex(buf, 0x1234);
    g_assert_true(str == buf + 4);
    g_assert_cmpint(str[-1], ==, '4');
    g_assert_cmpint(str[-2], ==, '3');
    g_assert_cmpint(str[-3], ==, '2');
    g_assert_cmpint(str[-4], ==, '1');

    str = dword_to_hex(buf, 0x1234);
    g_assert_true(str == buf + 8);
    g_assert_cmpint(str[-1], ==, '4');
    g_assert_cmpint(str[-2], ==, '3');
    g_assert_cmpint(str[-3], ==, '2');
    g_assert_cmpint(str[-4], ==, '1');
    g_assert_cmpint(str[-5], ==, '0');
    g_assert_cmpint(str[-6], ==, '0');
    g_assert_cmpint(str[-7], ==, '0');
    g_assert_cmpint(str[-8], ==, '0');

    str = qword_to_hex(buf, G_GUINT64_CONSTANT(0xFEDCBA987654321));
    g_assert_true(str == buf + 16);
    g_assert_cmpint(str[-1], ==, '1');
    g_assert_cmpint(str[-2], ==, '2');
    g_assert_cmpint(str[-3], ==, '3');
    g_assert_cmpint(str[-4], ==, '4');
    g_assert_cmpint(str[-5], ==, '5');
    g_assert_cmpint(str[-6], ==, '6');
    g_assert_cmpint(str[-7], ==, '7');
    g_assert_cmpint(str[-8], ==, '8');
    g_assert_cmpint(str[-9], ==, '9');
    g_assert_cmpint(str[-10], ==, 'a');
    g_assert_cmpint(str[-11], ==, 'b');
    g_assert_cmpint(str[-12], ==, 'c');
    g_assert_cmpint(str[-13], ==, 'd');
    g_assert_cmpint(str[-14], ==, 'e');
    g_assert_cmpint(str[-15], ==, 'f');
    g_assert_cmpint(str[-16], ==, '0');
}

static void test_bytes_to_str(void)
{
    char *str;

    const guint8 buf[] = { 1, 2, 3};

    str = bytes_to_str(NULL, buf, sizeof(buf));
    g_assert_cmpstr(str, ==, "010203");
    g_free(str);
}

static void test_bytes_to_str_punct(void)
{
    char *str;

    const guint8 buf[] = { 1, 2, 3};

    str = bytes_to_str_punct(NULL, buf, sizeof(buf), ':');
    g_assert_cmpstr(str, ==, "01:02:03");
    g_free(str);
}

static void test_bytes_to_str_punct_maxlen(void)
{
    char *str;

    const guint8 buf[] = { 1, 2, 3};

    str = bytes_to_str_punct_maxlen(NULL, buf, sizeof(buf), ':', 4);
    g_assert_cmpstr(str, ==, "01:02:03");
    g_free(str);

    str = bytes_to_str_punct_maxlen(NULL, buf, sizeof(buf), ':', 3);
    g_assert_cmpstr(str, ==, "01:02:03");
    g_free(str);

    str = bytes_to_str_punct_maxlen(NULL, buf, sizeof(buf), ':', 2);
    g_assert_cmpstr(str, ==, "01:02:" UTF8_HORIZONTAL_ELLIPSIS);
    g_free(str);

    str = bytes_to_str_punct_maxlen(NULL, buf, sizeof(buf), ':', 1);
    g_assert_cmpstr(str, ==, "01:" UTF8_HORIZONTAL_ELLIPSIS);
    g_free(str);

    str = bytes_to_str_punct_maxlen(NULL, buf, sizeof(buf), ':', 0);
    g_assert_cmpstr(str, ==, "01:02:03");
    g_free(str);
}

static void test_bytes_to_str_maxlen(void)
{
    char *str;

    const guint8 buf[] = { 1, 2, 3};

    str = bytes_to_str_maxlen(NULL, buf, sizeof(buf), 4);
    g_assert_cmpstr(str, ==, "010203");
    g_free(str);

    str = bytes_to_str_maxlen(NULL, buf, sizeof(buf), 3);
    g_assert_cmpstr(str, ==, "010203");
    g_free(str);

    str = bytes_to_str_maxlen(NULL, buf, sizeof(buf), 2);
    g_assert_cmpstr(str, ==, "0102" UTF8_HORIZONTAL_ELLIPSIS);
    g_free(str);

    str = bytes_to_str_maxlen(NULL, buf, sizeof(buf), 1);
    g_assert_cmpstr(str, ==, "01" UTF8_HORIZONTAL_ELLIPSIS);
    g_free(str);

    str = bytes_to_str_maxlen(NULL, buf, sizeof(buf), 0);
    g_assert_cmpstr(str, ==, "010203");
    g_free(str);
}

static void test_bytes_to_string_trunc1(void)
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

static void test_bytes_to_string_punct_trunc1(void)
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

static void test_oct_to_str_back(void)
{
    char *str;

    str = oct_to_str_back(BACK_PTR, 958769886);
    g_assert_cmpstr(str,  ==, "07111325336");

    str = oct_to_str_back(BACK_PTR, 781499127);
    g_assert_cmpstr(str,  ==, "05645135367");

    str = oct_to_str_back(BACK_PTR, 1177329882);
    g_assert_cmpstr(str, ==, "010613120332");
}

static void test_oct64_to_str_back(void)
{
    char *str;

    str = oct64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(13873797580070999420));
    g_assert_cmpstr(str, ==, "01402115026217563452574");

    str = oct64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(7072159458371400691));
    g_assert_cmpstr(str, ==, "0610452670726711271763");

    str = oct64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(12453513102400590374));
    g_assert_cmpstr(str, ==, "01263236102754220511046");
}

static void test_hex_to_str_back_len(void)
{
    char *str;

    str = hex_to_str_back_len(BACK_PTR, 2481, 8);
    g_assert_cmpstr(str, ==, "0x000009b1");

    str = hex_to_str_back_len(BACK_PTR, 2457, 8);
    g_assert_cmpstr(str, ==, "0x00000999");

    str = hex_to_str_back_len(BACK_PTR, 16230, 8);
    g_assert_cmpstr(str, ==, "0x00003f66");
}

static void test_hex64_to_str_back_len(void)
{
    char *str;

    str = hex64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(1), 16);
    g_assert_cmpstr(str, ==, "0x0000000000000001");

    str = hex64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(4294967295), 16);
    g_assert_cmpstr(str, ==, "0x00000000ffffffff");

    str = hex64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(18446744073709551615), 16);
    g_assert_cmpstr(str, ==, "0xffffffffffffffff");
}

static void test_uint_to_str_back(void)
{
    char *str;

    str = uint_to_str_back(BACK_PTR, 873735883);
    g_assert_cmpstr(str, ==, "873735883");

    str = uint_to_str_back(BACK_PTR, 1801148094);
    g_assert_cmpstr(str, ==, "1801148094");

    str = uint_to_str_back(BACK_PTR, 181787997);
    g_assert_cmpstr(str, ==, "181787997");
}

static void test_uint64_to_str_back(void)
{
    char *str;

    str = uint64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(585143757104211265));
    g_assert_cmpstr(str, ==, "585143757104211265");

    str = uint64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(7191580247919484847));
    g_assert_cmpstr(str, ==, "7191580247919484847");

    str = uint64_to_str_back(BACK_PTR, G_GUINT64_CONSTANT(95778573911934485));
    g_assert_cmpstr(str, ==, "95778573911934485");
}

static void test_uint_to_str_back_len(void)
{
    char *str;

    str = uint_to_str_back_len(BACK_PTR, 26630, 8);
    g_assert_cmpstr(str, ==, "00026630");

    str = uint_to_str_back_len(BACK_PTR, 25313, 8);
    g_assert_cmpstr(str, ==, "00025313");

    str = uint_to_str_back_len(BACK_PTR, 18750000, 8);
    g_assert_cmpstr(str, ==, "18750000");
}

static void test_uint64_to_str_back_len(void)
{
    char *str;

    str = uint64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(1), 16);
    g_assert_cmpstr(str, ==, "0000000000000001");

    str = uint64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(4294967295), 16);
    g_assert_cmpstr(str, ==, "0000004294967295");

    str = uint64_to_str_back_len(BACK_PTR, G_GUINT64_CONSTANT(18446744073709551615), 16);
    g_assert_cmpstr(str, ==, "18446744073709551615");
}

static void test_int_to_str_back(void)
{
    char *str;

    str = int_to_str_back(BACK_PTR, -763689611);
    g_assert_cmpstr(str, ==, "-763689611");

    str = int_to_str_back(BACK_PTR, -296015954);
    g_assert_cmpstr(str, ==, "-296015954");

    str = int_to_str_back(BACK_PTR, 898901469);
    g_assert_cmpstr(str, ==, "898901469");
}

static void test_int64_to_str_back(void)
{
    char *str;

    str = int64_to_str_back(BACK_PTR, G_GINT64_CONSTANT(-9223372036854775807));
    g_assert_cmpstr(str, ==, "-9223372036854775807");

    str = int64_to_str_back(BACK_PTR, G_GINT64_CONSTANT(1));
    g_assert_cmpstr(str, ==, "1");

    str = int64_to_str_back(BACK_PTR, G_GINT64_CONSTANT(9223372036854775807));
    g_assert_cmpstr(str, ==, "9223372036854775807");
}

#include "nstime.h"
#include "time_util.h"

void test_nstime_from_iso8601(void)
{
    char *str;
    size_t chars;
    nstime_t result, expect;
    struct tm tm1;

    memset(&tm1, 0, sizeof(tm1));
    tm1.tm_sec = 25;
    tm1.tm_min = 45;
    tm1.tm_hour = 23;
    tm1.tm_mday = 30;
    tm1.tm_mon = 4; /* starts at zero */
    tm1.tm_year = 2013 - 1900;
    tm1.tm_isdst = -1;

    /* Date and time with local time. */
    str = "2013-05-30T23:45:25.349124";
    expect.secs = mktime(&tm1);
    expect.nsecs = 349124 * 1000;
    chars = iso8601_to_nstime(&result, str, ISO8601_DATETIME_AUTO);
    g_assert_cmpuint(chars, ==, strlen(str));
    g_assert_cmpint(result.secs, ==, expect.secs);
    g_assert_cmpint(result.nsecs, ==, expect.nsecs);

    /* Date and time with UTC timezone. */
    str = "2013-05-30T23:45:25.349124Z";
    expect.secs = mktime_utc(&tm1);
    expect.nsecs = 349124 * 1000;
    chars = iso8601_to_nstime(&result, str, ISO8601_DATETIME_AUTO);
    g_assert_cmpuint(chars, ==, strlen(str));
    g_assert_cmpint(result.secs, ==, expect.secs);
    g_assert_cmpint(result.nsecs, ==, expect.nsecs);

    /* Date and time with timezone offset with separator. */
    str = "2013-05-30T23:45:25.349124+01:00";
    expect.secs = mktime_utc(&tm1) - 1 * 60 * 60;
    expect.nsecs = 349124 * 1000;
    chars = iso8601_to_nstime(&result, str, ISO8601_DATETIME_AUTO);
    g_assert_cmpuint(chars, ==, strlen(str));
    g_assert_cmpint(result.secs, ==, expect.secs);
    g_assert_cmpint(result.nsecs, ==, expect.nsecs);

    /* Date and time with timezone offset without separator. */
    str = "2013-05-30T23:45:25.349124+0100";
    expect.secs = mktime_utc(&tm1) - 1 * 60 * 60;
    expect.nsecs = 349124 * 1000;
    chars = iso8601_to_nstime(&result, str, ISO8601_DATETIME_AUTO);
    g_assert_cmpuint(chars, ==, strlen(str));
    g_assert_cmpint(result.secs, ==, expect.secs);
    g_assert_cmpint(result.nsecs, ==, expect.nsecs);

    /* Date and time with timezone offset with hours only. */
    str = "2013-05-30T23:45:25.349124+01";
    expect.secs = mktime_utc(&tm1) - 1 * 60 * 60;
    expect.nsecs = 349124 * 1000;
    chars = iso8601_to_nstime(&result, str, ISO8601_DATETIME_AUTO);
    g_assert_cmpuint(chars, ==, strlen(str));
    g_assert_cmpint(result.secs, ==, expect.secs);
    g_assert_cmpint(result.nsecs, ==, expect.nsecs);
}

#include "ws_getopt.h"

#define ARGV_MAX 31

static char **new_argv(int *argc_ptr, const char *args, ...)
{
    char **argv;
    int argc = 0;
    va_list ap;

    argv = g_malloc((ARGV_MAX + 1) * sizeof(char *));

    va_start(ap, args);
    while (args != NULL) {
        /* Increase ARGV_MAX or use a dynamic size if this assertion fails. */
        g_assert_true(argc < ARGV_MAX);
        argv[argc++] = g_strdup(args);
        args = va_arg(ap, const char *);
    }
    argv[argc] = NULL;
    va_end(ap);

    *argc_ptr = argc;
    return argv;
}

static void free_argv(char **argv)
{
    for (char **p = argv; *p != NULL; p++) {
        g_free(*p);
    }
    g_free(argv);
}

static void test_getopt_long_basic1(void)
{
    char **argv;
    int argc;

    const char *optstring = "ab:c";
    argv = new_argv(&argc, "/bin/ls", "-a", "-b", "arg1", "-c", "path", (char *)NULL);

    ws_optind = 1;
    int opt;

    opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
    g_assert_cmpint(opt, ==, 'a');
    g_assert_null(ws_optarg);

    opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
    g_assert_cmpint(opt, ==, 'b');
    g_assert_cmpstr(ws_optarg, ==, "arg1");

    opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
    g_assert_cmpint(opt, ==, 'c');
    g_assert_null(ws_optarg);

    opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
    g_assert_cmpint(opt, ==, -1);

    free_argv(argv);
}

static void test_getopt_long_basic2(void)
{
    char **argv;
    int argc;

    struct ws_option longopts[] = {
        { "opt1", ws_no_argument, NULL, '1' },
        { "opt2", ws_required_argument, NULL, '2' },
        { "opt3", ws_required_argument, NULL, '3' },
        { 0, 0, 0, 0 }
    };
    argv = new_argv(&argc, "/bin/ls", "--opt1", "--opt2", "arg1", "--opt3=arg2", "path", (char *)NULL);

    ws_optind = 1;
    int opt;

    opt = ws_getopt_long(argc, argv, "", longopts, NULL);
    g_assert_cmpint(opt, ==, '1');
    g_assert_null(ws_optarg);

    opt = ws_getopt_long(argc, argv, "", longopts, NULL);
    g_assert_cmpint(opt, ==, '2');
    g_assert_cmpstr(ws_optarg, ==, "arg1");

    opt = ws_getopt_long(argc, argv, "", longopts, NULL);
    g_assert_cmpint(opt, ==, '3');
    g_assert_cmpstr(ws_optarg, ==, "arg2");

    opt = ws_getopt_long(argc, argv, "", longopts, NULL);
    g_assert_cmpint(opt, ==, -1);

    free_argv(argv);
}

static void test_getopt_optional_argument1(void)
{
    char **argv;
    int argc;
    int opt;

    struct ws_option longopts_optional[] = {
        { "optional", ws_optional_argument, NULL, '1' },
        { 0, 0, 0, 0 }
    };

    argv = new_argv(&argc, "/bin/ls", "--optional=arg1", (char *)NULL);

    ws_optreset = 1;
    opt = ws_getopt_long(argc, argv, "", longopts_optional, NULL);
    g_assert_cmpint(opt, ==, '1');
    g_assert_cmpstr(ws_optarg, ==, "arg1");

    free_argv(argv);
    argv = new_argv(&argc, "/bin/ls", "--optional", "arg1", (char *)NULL);

    ws_optreset = 1;
    opt = ws_getopt_long(argc, argv, "", longopts_optional, NULL);
    g_assert_cmpint(opt, ==, '1');
    /* Optional argument does not recognize the form "--arg param" (it's ambiguous). */
    g_assert_null(ws_optarg);

    free_argv(argv);
    argv = new_argv(&argc, "/bin/ls", "--optional", (char *)NULL);

    ws_optreset = 1;
    opt = ws_getopt_long(argc, argv, "", longopts_optional, NULL);
    g_assert_cmpint(opt, ==, '1');
    g_assert_null(ws_optarg);

    free_argv(argv);
}

static void test_getopt_opterr1(void)
{
    char **argv;
    int argc;

#ifdef _WIN32
    g_test_skip("Not supported on Windows");
    return;
#endif

    if (g_test_subprocess()) {
        const char *optstring = "ab";
        argv = new_argv(&argc, "/bin/ls", "-a", "-z", "path", (char *)NULL);

        ws_optind = 0;
        ws_opterr = 1;
        int opt;

        opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
        g_assert_cmpint(opt, ==, 'a');

        opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
        g_assert_cmpint(opt, ==, '?');
        g_assert_cmpint(ws_optopt, ==, 'z');

        opt = ws_getopt_long(argc, argv, optstring, NULL, NULL);
        g_assert_cmpint(opt, ==, -1);

        free_argv(argv);

        return;
    }

    g_test_trap_subprocess(NULL, 0, 0);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("/bin/ls: unrecognized option: z\n");
}

int main(int argc, char **argv)
{
    int ret;

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/inet_addr/inet_pton4", test_inet_pton4_test1);
    g_test_add_func("/inet_addr/inet_ntop4", test_inet_ntop4_test1);
    g_test_add_func("/inet_addr/inet_pton6", test_inet_pton6_test1);
    g_test_add_func("/inet_addr/inet_ntop6", test_inet_ntop6_test1);

    g_test_add_func("/str_util/format_size", test_format_size);
    g_test_add_func("/str_util/escape_string", test_escape_string);
    g_test_add_func("/str_util/strconcat", test_strconcat);
    g_test_add_func("/str_util/strsplit", test_strsplit);
    g_test_add_func("/str_util/str_ascii", test_str_ascii);

    g_test_add_func("/to_str/word_to_hex", test_word_to_hex);
    g_test_add_func("/to_str/bytes_to_str", test_bytes_to_str);
    g_test_add_func("/to_str/bytes_to_str_punct", test_bytes_to_str_punct);
    g_test_add_func("/to_str/bytes_to_str_maxlen", test_bytes_to_str_maxlen);
    g_test_add_func("/to_str/bytes_to_str_punct_maxlen", test_bytes_to_str_punct_maxlen);
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

    g_test_add_func("/nstime/from_iso8601", test_nstime_from_iso8601);

    g_test_add_func("/ws_getopt/basic1", test_getopt_long_basic1);
    g_test_add_func("/ws_getopt/basic2", test_getopt_long_basic2);
    g_test_add_func("/ws_getopt/optional1", test_getopt_optional_argument1);
    g_test_add_func("/ws_getopt/opterr1", test_getopt_opterr1);

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
