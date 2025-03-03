/* wscbor_enc_test.c
 * Wireshark CBOR encoder API tests
 * Copyright 2025, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#undef G_DISABLE_ASSERT

#include <wsutil/array.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "wscbor_enc.h"

/*
 * These test are organized in order of the appearance, in wscbor_enc.h, of
 * the basic functions that they test.  This makes it easier to
 * get a quick understanding of both the testing and the organization
 * of the header.
 */

/* WSCBOR ENCODER TESTING FUNCTIONS (/wscbor_enc/) */

static void
wscbor_enc_test_undefined(void)
{
    GByteArray *buf = g_byte_array_new();
    g_assert_nonnull(buf);

    wscbor_enc_undefined(buf);
    const uint8_t expect[] = { 0xF7 };

    GBytes *data = g_byte_array_free_to_bytes(buf);
    g_assert_nonnull(data);
    g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                    expect, (int)sizeof(expect));

    g_bytes_unref(data);
}

static void
wscbor_enc_test_null(void)
{
    GByteArray *buf = g_byte_array_new();
    g_assert_nonnull(buf);

    wscbor_enc_null(buf);
    const uint8_t expect[] = { 0xF6 };

    GBytes *data = g_byte_array_free_to_bytes(buf);
    g_assert_nonnull(data);
    g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                    expect, (int)sizeof(expect));

    g_bytes_unref(data);
}

static void
wscbor_enc_test_boolean(void)
{
    for (size_t inp_ix = 0; inp_ix < 2; ++inp_ix) {

        GByteArray *buf = g_byte_array_new();
        g_assert_nonnull(buf);

        wscbor_enc_boolean(buf, inp_ix == 1);
        const uint8_t expect[] = { inp_ix ? 0xF5 : 0xF4 };

        GBytes *data = g_byte_array_free_to_bytes(buf);
        g_assert_nonnull(data);
        g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                        expect, (int)sizeof(expect));

        g_bytes_unref(data);
    }
}

typedef struct {
    int64_t value;
    // Raw bytes expected
    int enc_len;
    const uint8_t *enc;
} wscbor_enc_test_int64_t;

static const wscbor_enc_test_int64_t input_int64[] = {
    { INT64_MIN, 9, (const uint8_t *)"\x3B\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
    { -0x100000001, 9, (const uint8_t *)"\x3B\x00\x00\x00\x01\x00\x00\x00\x00"},
    { -0x100000000, 5, (const uint8_t *)"\x3A\xFF\xFF\xFF\xFF"},
    { -0x10001, 5, (const uint8_t *)"\x3A\x00\x01\x00\x00"},
    { -0x10000, 3, (const uint8_t *)"\x39\xFF\xFF"},
    { -0x101, 3, (const uint8_t *)"\x39\x01\x00"},
    { -0x100, 2, (const uint8_t *)"\x38\xFF"},
    { -25, 2, (const uint8_t *)"\x38\x18"},
    { -24, 1, (const uint8_t *)"\x37"},
    { -1, 1, (const uint8_t *)"\x20"},
    { 0, 1, (const uint8_t *)"\x00"},
    { 1, 1, (const uint8_t *)"\x01"},
    { 23, 1, (const uint8_t *)"\x17"},
    { 24, 2, (const uint8_t *)"\x18\x18"},
    { 0xFF, 2, (const uint8_t *)"\x18\xFF"},
    { 0x100, 3, (const uint8_t *)"\x19\x01\x00"},
    { 0xFFFF, 3, (const uint8_t *)"\x19\xFF\xFF"},
    { 0x10000, 5, (const uint8_t *)"\x1A\x00\x01\x00\x00"},
    { 0xFFFFFFFF, 5, (const uint8_t *)"\x1A\xFF\xFF\xFF\xFF"},
    { 0x100000000, 9, (const uint8_t *)"\x1B\x00\x00\x00\x01\x00\x00\x00\x00"},
    { INT64_MAX, 9, (const uint8_t *)"\x1B\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
};

static void
wscbor_enc_test_int64(void)
{
    for (size_t inp_ix = 0; inp_ix < array_length(input_int64); ++inp_ix) {
        const wscbor_enc_test_int64_t *inp = &input_int64[inp_ix];
        printf("case #%zu with %"PRId64"\n", inp_ix, inp->value);

        GByteArray *buf = g_byte_array_new();
        g_assert_nonnull(buf);

        wscbor_enc_int64(buf, inp->value);

        GBytes *data = g_byte_array_free_to_bytes(buf);
        g_assert_nonnull(data);
        g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                        inp->enc, (int)inp->enc_len);

        g_bytes_unref(data);
    }
}

typedef struct {
    uint64_t value;
    // Raw bytes expected
    int enc_len;
    const uint8_t *enc;
} wscbor_enc_test_uint64_t;

static const wscbor_enc_test_uint64_t input_uint64[] = {
    { 0, 1, (const uint8_t *)"\x00"},
    { 1, 1, (const uint8_t *)"\x01"},
    { 23, 1, (const uint8_t *)"\x17"},
    { 24, 2, (const uint8_t *)"\x18\x18"},
    { 0xFF, 2, (const uint8_t *)"\x18\xFF"},
    { 0x100, 3, (const uint8_t *)"\x19\x01\x00"},
    { 0xFFFF, 3, (const uint8_t *)"\x19\xFF\xFF"},
    { 0x10000, 5, (const uint8_t *)"\x1A\x00\x01\x00\x00"},
    { 0xFFFFFFFF, 5, (const uint8_t *)"\x1A\xFF\xFF\xFF\xFF"},
    { 0x100000000, 9, (const uint8_t *)"\x1B\x00\x00\x00\x01\x00\x00\x00\x00"},
    { INT64_MAX, 9, (const uint8_t *)"\x1B\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
    { UINT64_MAX, 9, (const uint8_t *)"\x1B\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"},
};

static void
wscbor_enc_test_uint64(void)
{
    for (size_t inp_ix = 0; inp_ix < array_length(input_uint64); ++inp_ix) {
        const wscbor_enc_test_uint64_t *inp = &input_uint64[inp_ix];
        printf("case #%zu with %"PRIu64"\n", inp_ix, inp->value);

        GByteArray *buf = g_byte_array_new();
        g_assert_nonnull(buf);

        wscbor_enc_uint64(buf, inp->value);

        GBytes *data = g_byte_array_free_to_bytes(buf);
        g_assert_nonnull(data);
        g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                        inp->enc, (int)inp->enc_len);

        g_bytes_unref(data);
    }
}

typedef struct {
    const size_t len;
    const uint8_t *ptr;
    // Raw bytes expected
    int enc_len;
    const uint8_t *enc;
} wscbor_enc_test_bstr_t;

static const wscbor_enc_test_bstr_t input_bstr[] = {
    { 0, (const uint8_t *)"", 1, (const uint8_t *)"\x40"},
    { 1, (const uint8_t *)"\x10", 2, (const uint8_t *)"\x41\x10"},
    { 5, (const uint8_t *)"\x01\x02\x03\x04\x05", 6, (const uint8_t *)"\x45\x01\x02\x03\x04\x05"},
};

static void
wscbor_enc_test_bstr(void)
{
    for (size_t inp_ix = 0; inp_ix < array_length(input_bstr); ++inp_ix) {
        const wscbor_enc_test_bstr_t *inp = &input_bstr[inp_ix];
        printf("case #%zu with %zu bytes\n", inp_ix, inp->len);

        GByteArray *buf = g_byte_array_new();
        g_assert_nonnull(buf);

        wscbor_enc_bstr(buf, inp->ptr, inp->len);

        GBytes *data = g_byte_array_free_to_bytes(buf);
        g_assert_nonnull(data);
        g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                        inp->enc, (int)inp->enc_len);

        g_bytes_unref(data);
    }
}

typedef struct {
    const char *ptr;
    // Raw bytes expected
    int enc_len;
    const uint8_t *enc;
} wscbor_enc_test_tstr_t;

static const wscbor_enc_test_tstr_t input_tstr[] = {
    { "", 1, (const uint8_t *)"\x60"},
    { "hello", 6, (const uint8_t *)"\x65\x68\x65\x6C\x6C\x6F"},
};

static void
wscbor_enc_test_tstr(void)
{
    for (size_t inp_ix = 0; inp_ix < array_length(input_tstr); ++inp_ix) {
        const wscbor_enc_test_tstr_t *inp = &input_tstr[inp_ix];
        printf("case #%zu with %zu bytes\n", inp_ix, strlen(inp->ptr));

        GByteArray *buf = g_byte_array_new();
        g_assert_nonnull(buf);

        wscbor_enc_tstr(buf, inp->ptr);

        GBytes *data = g_byte_array_free_to_bytes(buf);
        g_assert_nonnull(data);
        g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                        inp->enc, (int)inp->enc_len);

        g_bytes_unref(data);
    }
}

static void
wscbor_enc_test_array(void)
{
    GByteArray *buf = g_byte_array_new();
    g_assert_nonnull(buf);

    wscbor_enc_array_head(buf, 2);
    wscbor_enc_int64(buf, 10);
    wscbor_enc_int64(buf, -10);

    GBytes *data = g_byte_array_free_to_bytes(buf);
    g_assert_nonnull(data);
    g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                    "\x82\x0A\x29", (int)3);

    g_bytes_unref(data);
}

static void
wscbor_enc_test_map(void)
{
    GByteArray *buf = g_byte_array_new();
    g_assert_nonnull(buf);

    wscbor_enc_map_head(buf, 1);
    wscbor_enc_int64(buf, 10);
    wscbor_enc_tstr(buf, "hi");

    GBytes *data = g_byte_array_free_to_bytes(buf);
    g_assert_nonnull(data);
    g_assert_cmpmem(g_bytes_get_data(data, NULL), (int)g_bytes_get_size(data),
                    "\xA1\x0A\x62\x68\x69", (int)5);

    g_bytes_unref(data);
}

int
main(int argc, char **argv)
{
    int result;

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/wscbor_enc/undefined", wscbor_enc_test_undefined);
    g_test_add_func("/wscbor_enc/null", wscbor_enc_test_null);
    g_test_add_func("/wscbor_enc/boolean", wscbor_enc_test_boolean);
    g_test_add_func("/wscbor_enc/int64", wscbor_enc_test_int64);
    g_test_add_func("/wscbor_enc/uint64", wscbor_enc_test_uint64);
    g_test_add_func("/wscbor_enc/bstr", wscbor_enc_test_bstr);
    g_test_add_func("/wscbor_enc/tstr", wscbor_enc_test_tstr);
    g_test_add_func("/wscbor_enc/array", wscbor_enc_test_array);
    g_test_add_func("/wscbor_enc/map", wscbor_enc_test_map);

    result = g_test_run();

    return result;
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
