/* wsjson.c
 * JSON parsing functions.
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_MAIN

#include "wsjson.h"

#include <string.h>
#include <errno.h>
#include <wsutil/jsmn.h>
#include <wsutil/str_util.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/wslog.h>

gboolean
json_validate(const guint8 *buf, const size_t len)
{
    gboolean ret = TRUE;
    /* We expect no more than 1024 tokens */
    guint max_tokens = 1024;
    jsmntok_t* t;
    jsmn_parser p;
    int rcode;

    /*
     * Make sure the buffer isn't empty and the first octet isn't a NUL;
     * otherwise, the parser will immediately stop parsing and not validate
     * anything after that, so it'll just think it was handed an empty string.
     *
     * XXX - should we check for NULs anywhere in the buffer?
     */
    if (len == 0) {
        ws_debug("JSON string is empty");
        return FALSE;
    }
    if (buf[0] == '\0') {
        ws_debug("invalid character inside JSON string");
        return FALSE;
    }

    t = g_new0(jsmntok_t, max_tokens);

    if (!t)
        return FALSE;

    jsmn_init(&p);
    rcode = jsmn_parse(&p, buf, len, t, max_tokens);
    if (rcode < 0) {
        switch (rcode) {
            case JSMN_ERROR_NOMEM:
                ws_debug("not enough tokens were provided");
                break;
            case JSMN_ERROR_INVAL:
                ws_debug("invalid character inside JSON string");
                break;
            case JSMN_ERROR_PART:
                ws_debug("the string is not a full JSON packet, "
                    "more bytes expected");
                break;
            default:
                ws_debug("unexpected error");
                break;
        }
        ret = FALSE;
    }

    g_free(t);
    return ret;
}

int
json_parse(const char *buf, jsmntok_t *tokens, unsigned int max_tokens)
{
    jsmn_parser p;

    jsmn_init(&p);
    return jsmn_parse(&p, buf, strlen(buf), tokens, max_tokens);
}

static
jsmntok_t *json_get_next_object(jsmntok_t *cur)
{
    int i;
    jsmntok_t *next = cur+1;

    for (i = 0; i < cur->size; i++) {
        next = json_get_next_object(next);
    }
    return next;
}

jsmntok_t *json_get_object(const char *buf, jsmntok_t *parent, const char *name)
{
    int i;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_OBJECT) {
            return cur+1;
        }
        cur = json_get_next_object(cur);
    }
    return NULL;
}

jsmntok_t *json_get_array(const char *buf, jsmntok_t *parent, const char *name)
{
    int i;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_ARRAY) {
            return cur+1;
        }
        cur = json_get_next_object(cur);
    }
    return NULL;
}

int json_get_array_len(jsmntok_t *array)
{
    if (array->type != JSMN_ARRAY)
        return -1;
    return array->size;
}

jsmntok_t *json_get_array_index(jsmntok_t *array, int idx)
{
    int i;
    jsmntok_t *cur = array+1;


    if (array->type != JSMN_ARRAY || idx < 0 || idx >= array->size)
        return NULL;
    for (i = 0; i < idx; i++)
        cur = json_get_next_object(cur);
    return cur;
}

char *json_get_string(char *buf, jsmntok_t *parent, const char *name)
{
    int i;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_STRING) {
            buf[(cur+1)->end] = '\0';
            if (!json_decode_string_inplace(&buf[(cur+1)->start]))
                return NULL;
            return &buf[(cur+1)->start];
        }
        cur = json_get_next_object(cur);
    }
    return NULL;
}

gboolean json_get_double(char *buf, jsmntok_t *parent, const char *name, gdouble *val)
{
    int i;
    jsmntok_t *cur = parent+1;

    for (i = 0; i < parent->size; i++) {
        if (cur->type == JSMN_STRING &&
            !strncmp(&buf[cur->start], name, cur->end - cur->start)
            && strlen(name) == (size_t)(cur->end - cur->start) &&
            cur->size == 1 && (cur+1)->type == JSMN_PRIMITIVE) {
            buf[(cur+1)->end] = '\0';
            *val = g_ascii_strtod(&buf[(cur+1)->start], NULL);
            if (errno != 0)
                return FALSE;
            return TRUE;
        }
        cur = json_get_next_object(cur);
    }
    return FALSE;
}

gboolean
json_decode_string_inplace(char *text)
{
    const char *input = text;
    char *output = text;
    while (*input) {
        char ch = *input++;

        if (ch == '\\') {
            ch = *input++;

            switch (ch) {
                case '\"':
                case '\\':
                case '/':
                    *output++ = ch;
                    break;

                case 'b':
                    *output++ = '\b';
                    break;
                case 'f':
                    *output++ = '\f';
                    break;
                case 'n':
                    *output++ = '\n';
                    break;
                case 'r':
                    *output++ = '\r';
                    break;
                case 't':
                    *output++ = '\t';
                    break;

                case 'u':
                {
                    guint32 unicode_hex = 0;
                    int k;
                    int bin;

                    for (k = 0; k < 4; k++) {
                        unicode_hex <<= 4;

                        ch = *input++;
                        bin = ws_xton(ch);
                        if (bin == -1)
                            return FALSE;
                        unicode_hex |= bin;
                    }

                    if ((IS_LEAD_SURROGATE(unicode_hex))) {
                        guint16 lead_surrogate = unicode_hex;
                        guint16 trail_surrogate = 0;

                        if (input[0] != '\\' || input[1] != 'u')
                            return FALSE;
                        input += 2;

                        for (k = 0; k < 4; k++) {
                            trail_surrogate <<= 4;

                            ch = *input++;
                            bin = ws_xton(ch);
                            if (bin == -1)
                                return FALSE;
                            trail_surrogate |= bin;
                        }

                        if ((!IS_TRAIL_SURROGATE(trail_surrogate)))
                            return FALSE;

                        unicode_hex = SURROGATE_VALUE(lead_surrogate,trail_surrogate);

                    } else if ((IS_TRAIL_SURROGATE(unicode_hex))) {
                        return FALSE;
                    }

                    if (!g_unichar_validate(unicode_hex))
                        return FALSE;

                    /* Don't allow NUL byte injection. */
                    if (unicode_hex == 0)
                        return FALSE;

                    /* \uXXXX => 6 bytes, and g_unichar_to_utf8() requires to have output buffer at least 6 bytes -> OK. */
                    k = g_unichar_to_utf8(unicode_hex, output);
                    output += k;
                    break;
                }

                default:
                    return FALSE;
            }

        } else {
            *output = ch;
            output++;
        }
    }

    *output = '\0';
    return TRUE;
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
