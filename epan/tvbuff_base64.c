/* tvbuff_base64.c
 * Base-64 tvbuff implementation (based on real tvb)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/tvbuff.h>
#include "proto.h"

/* Copy of glib function modified for base64uri */

static const unsigned char mime_base64uri_rank[256] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255, 255,255,63,255,255,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};
 /**
  * Copy of glib function modified for base64uri
  * g_base64uri_decode_step: (skip)
  * @in: (array length=len) (element-type uint8_t): binary input data
  * @len: max length of @in data to decode
  * @out: (out caller-allocates) (array) (element-type uint8_t): output buffer
  * @state: (inout): Saved state between steps, initialize to 0
  * @save: (inout): Saved state between steps, initialize to 0
  *
  * Incrementally decode a sequence of binary data from its Base-64 stringified
  * representation. By calling this function multiple times you can convert
  * data in chunks to avoid having to have the full encoded data in memory.
  *
  * The output buffer must be large enough to fit all the data that will
  * be written to it. Since base64 encodes 3 bytes in 4 chars you need
  * at least: (@len / 4) * 3 + 3 bytes (+ 3 may be needed in case of non-zero
  * state).
  *
  * Returns: The number of bytes of output that was written
  *
  * Since: 2.12
  **/
static size_t
g_base64uri_decode_step(const char* in,
    size_t        len,
    unsigned char* out,
    int* state,
    unsigned* save)
{
    const unsigned char* inptr;
    unsigned char* outptr;
    const unsigned char* inend;
    unsigned char c, rank;
    unsigned char last[2];
    unsigned int v;
    int i;

    g_return_val_if_fail(in != NULL || len == 0, 0);
    g_return_val_if_fail(out != NULL, 0);
    g_return_val_if_fail(state != NULL, 0);
    g_return_val_if_fail(save != NULL, 0);

    if (len == 0)
        return 0;

    inend = (const unsigned char*)in + len;
    outptr = out;

    /* convert 4 base64 bytes to 3 normal bytes */
    v = *save;
    i = *state;

    last[0] = last[1] = 0;

    /* we use the sign in the state to determine if we got a padding character
       in the previous sequence */
    if (i < 0)
    {
        i = -i;
        last[0] = '=';
    }

    inptr = (const unsigned char*)in;
    while (inptr < inend)
    {
        c = *inptr++;
        rank = mime_base64uri_rank[c];
        if (rank != 0xff)
        {
            last[1] = last[0];
            last[0] = c;
            v = (v << 6) | rank;
            i++;
            if (i == 4)
            {
                *outptr++ = v >> 16;
                if (last[1] != '=')
                    *outptr++ = v >> 8;
                if (last[0] != '=')
                    *outptr++ = v;
                i = 0;
            }
        }
    }

    *save = v;
    *state = last[0] == '=' ? -i : i;

    return outptr - out;
}
 /**
  * Copy of glib function modified for base64uri
  * g_base64uri_decode:
  * @text: (not nullable): zero-terminated string with base64 text to decode
  * @out_len: (out): The length of the decoded data is written here
  *
  * Decode a sequence of Base-64 encoded text into binary data.  Note
  * that the returned binary data is not necessarily zero-terminated,
  * so it should not be used as a character string.
  *
  * Returns: (transfer full) (array length=out_len) (element-type uint8_t):
  *               newly allocated buffer containing the binary data
  *               that @text represents. The returned buffer must
  *               be freed with g_free().
  *
  * Since: 2.12
  */
static unsigned char*
g_base64uri_decode(const char* text,
    size_t* out_len)
{
    unsigned char* ret;
    size_t input_length;
    int state = 0;
    unsigned save = 0;

    g_return_val_if_fail(text != NULL, NULL);
    g_return_val_if_fail(out_len != NULL, NULL);

    input_length = strlen(text);

    /* We can use a smaller limit here, since we know the saved state is 0,
       +1 used to avoid calling g_malloc0(0), and hence returning NULL */
    ret = (unsigned char * )g_malloc0((input_length / 4) * 3 + 1);

    *out_len = g_base64uri_decode_step(text, input_length, ret, &state, &save);

    return ret;
}

tvbuff_t *
base64_to_tvb(tvbuff_t *parent, const char *base64)
{
  tvbuff_t *tvb;
  char *data;
  size_t len;

  data = g_base64_decode(base64, &len);
  tvb = tvb_new_child_real_data(parent, (const uint8_t *)data, (int)len, (int)len);

  tvb_set_free_cb(tvb, g_free);

  return tvb;
}

tvbuff_t*
base64_tvb_to_new_tvb(tvbuff_t* parent, int offset, int length)
{
    tvbuff_t* tvb;
    char* data, *tmp;
    size_t len;

    tmp = tvb_get_string_enc(NULL, parent, offset, length, ENC_ASCII);
    data = g_base64_decode(tmp, &len);
    wmem_free(NULL, tmp);

    tvb = tvb_new_child_real_data(parent, (const uint8_t*)data, (int)len, (int)len);

    tvb_set_free_cb(tvb, g_free);

    return tvb;
}

tvbuff_t*
base64uri_tvb_to_new_tvb(tvbuff_t* parent, int offset, int length)
{
    tvbuff_t* tvb;
    char* data, *tmp;
    size_t len = 0;

    tmp = tvb_get_string_enc(NULL, parent, offset, length, ENC_ASCII);
    data = g_base64uri_decode(tmp, &len);
    wmem_free(NULL, tmp);

    tvb = tvb_new_child_real_data(parent, (const uint8_t*)data, (int)len, (int)len);

    tvb_set_free_cb(tvb, g_free);

    return tvb;
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
