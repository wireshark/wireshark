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

static char *
get_error_msg(int errorcode)
{
    char *buffer;

    /*
     * We have to provide a buffer and we don't know how long the
     * error message is or even the maximum size. From pcre2api(3):
     *     "None of the messages are very long; a
     *     buffer size of 120 code units is ample."
     */
    /* Code unit = one byte */
    buffer = g_malloc(ERROR_MAXLEN_IN_CODE_UNITS);
    /* Message is returned with a trailing zero. */
    pcre2_get_error_message(errorcode, buffer, ERROR_MAXLEN_IN_CODE_UNITS);
    /* One more at the end for good luck. */
    buffer[ERROR_MAXLEN_IN_CODE_UNITS-1] = '\0';
    return buffer;
}


static pcre2_code *
compile_pcre2(const char *patt, char **errmsg)
{
    pcre2_code *code;
    int errorcode;
    PCRE2_SIZE erroroffset;

    /* By default UTF-8 is off. */
    code = pcre2_compile_8((PCRE2_SPTR)patt,
                PCRE2_ZERO_TERMINATED,
                PCRE2_NEVER_UTF,
                &errorcode,
                &erroroffset,
                NULL);

    if (code == NULL) {
        *errmsg = get_error_msg(errorcode);
        return NULL;
    }

    return code;
}


ws_regex_t *
ws_regex_compile(const char *patt, char **errmsg)
{
    ws_return_val_if_null(patt, NULL);

    pcre2_code *code = compile_pcre2(patt, errmsg);
    if (code == NULL)
        return NULL;

    ws_regex_t *re = g_new(ws_regex_t, 1);
    re->code = code;
    re->pattern = g_strdup(patt);
    return re;
}


static bool
match_pcre2(pcre2_code *code, const char *subj, size_t subj_size)
{
    PCRE2_SIZE length;
    pcre2_match_data *match_data;
    int rc;

    length = subj_size == WS_REGEX_ZERO_TERMINATED ? PCRE2_ZERO_TERMINATED : (PCRE2_SIZE)subj_size;

    /* We don't use the matched substring but pcre2_match requires
     * at least one pair of offsets. */
    match_data = pcre2_match_data_create(1, NULL);

    rc = pcre2_match(code,
                    subj,
                    length,
                    0,          /* start at offset zero of the subject */
                    0,          /* default options */
                    match_data,
                    NULL);

    pcre2_match_data_free(match_data);

    if (rc < 0) {
        /* No match */
        if (rc != PCRE2_ERROR_NOMATCH) {
            /* Error. Should not happen with UTF-8 disabled. Some huge
             * subject strings could hit some internal limit. */
            char *msg = get_error_msg(rc);
            ws_debug("Unexpected pcre2_match() error: %s.", msg);
            g_free(msg);
        }
        return FALSE;
    }

    /* Matched */
    return TRUE;
}


bool
ws_regex_matches(const ws_regex_t *re, const char *subj, size_t subj_size)
{
    ws_return_val_if_null(re, FALSE);
    ws_return_val_if_null(subj, FALSE);

    return match_pcre2(re->code, subj, subj_size);
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
