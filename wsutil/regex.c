/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "regex.h"

#include <wsutil/ws_return.h>
#include <pcre2.h>


struct _ws_regex {
    pcre2_code *code;
    char *pattern;
};

#define ERROR_MAXLEN_IN_CODE_UNITS   128

static pcre2_code *
_pcre2_compile(const char *patt, char **errmsg)
{
    pcre2_code *code;
    int errorcode;
    PCRE2_SIZE erroroffset;
    char *error_buffer;

    /* By default UTF-8 is off. */
    code = pcre2_compile_8((PCRE2_SPTR)patt,
                PCRE2_ZERO_TERMINATED,
                PCRE2_NEVER_UTF,
                &errorcode,
                &erroroffset,
                NULL);

    if (code == NULL) {
        /*
         * We have to provide a buffer and we don't know how long the
         * error message is or even the maximum size. From pcre2api(3):
         *     "None of the messages are very long; a
         *     buffer size of 120 code units is ample."
         */
        /* Code unit = one byte */
        error_buffer = g_malloc(ERROR_MAXLEN_IN_CODE_UNITS);
        /* Message is returned with a trailing zero. */
        pcre2_get_error_message(errorcode, error_buffer, ERROR_MAXLEN_IN_CODE_UNITS);
        /* One more at the end for good luck. */
        error_buffer[ERROR_MAXLEN_IN_CODE_UNITS-1] = '\0';
        *errmsg = error_buffer;
        return NULL;
    }

    return code;
}


ws_regex_t *
ws_regex_compile(const char *patt, char **errmsg)
{
    ws_return_val_if_null(patt, NULL);

    pcre2_code *code = _pcre2_compile(patt, errmsg);
    if (code == NULL)
        return NULL;

    ws_regex_t *re = g_new(ws_regex_t, 1);
    re->code = code;
    re->pattern = g_strdup(patt);
    return re;
}


static bool
_pcre2_matches(pcre2_code *code, const char *subj, gssize subj_size)
{
    PCRE2_SIZE length;
    pcre2_match_data *match_data;
    int rc;

    length = subj_size < 0 ? PCRE2_ZERO_TERMINATED : (PCRE2_SIZE)subj_size;
    match_data = pcre2_match_data_create_from_pattern(code, NULL);

    rc = pcre2_match(code, subj, length, 0, 0, match_data, NULL);
    pcre2_match_data_free(match_data);

    return rc < 0 ? FALSE : TRUE;
}


bool
ws_regex_matches(const ws_regex_t *re, const char *subj, gssize subj_size)
{
    ws_return_val_if_null(re, FALSE);
    ws_return_val_if_null(subj, FALSE);

    return _pcre2_matches(re->code, subj, subj_size);
}


void
ws_regex_free(ws_regex_t *re)
{
    pcre2_code_free(re->code);
    g_free(re->pattern);
    g_free(re);
}


const char *
ws_regex_pattern(const ws_regex_t *re)
{
    return re->pattern;
}
