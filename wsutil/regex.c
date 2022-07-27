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
#include <wsutil/str_util.h>
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
compile_pcre2(const char *patt, ssize_t size, char **errmsg, unsigned flags)
{
    pcre2_code *code;
    int errorcode;
    PCRE2_SIZE length;
    PCRE2_SIZE erroroffset;
    uint32_t options = 0;

    if (size < 0)
        length = PCRE2_ZERO_TERMINATED;
    else
        length = (PCRE2_SIZE)size;

    if (flags & WS_REGEX_NEVER_UTF)
        options |= PCRE2_NEVER_UTF;
    if (flags & WS_REGEX_CASELESS)
        options |= PCRE2_CASELESS;

    /* By default UTF-8 is off. */
    code = pcre2_compile_8((PCRE2_SPTR)patt,
                length,
                options,
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
ws_regex_compile_ex(const char *patt, ssize_t size, char **errmsg, unsigned flags)
{
    ws_return_val_if_null(patt, NULL);

    pcre2_code *code = compile_pcre2(patt, size, errmsg, flags);
    if (code == NULL)
        return NULL;

    ws_regex_t *re = g_new(ws_regex_t, 1);
    re->code = code;
    re->pattern = ws_escape_string_len(NULL, patt, size, false);
    return re;
}


ws_regex_t *
ws_regex_compile(const char *patt, char **errmsg)
{
    return ws_regex_compile_ex(patt, -1, errmsg, 0);
}


static bool
match_pcre2(pcre2_code *code, const char *subject, ssize_t subj_length,
                pcre2_match_data *match_data)
{
    PCRE2_SIZE length;
    int rc;

    if (subj_length < 0)
        length = PCRE2_ZERO_TERMINATED;
    else
        length = (PCRE2_SIZE)subj_length;

    rc = pcre2_match(code,
                    subject,
                    length,
                    0,          /* start at offset zero of the subject */
                    0,          /* default options */
                    match_data,
                    NULL);

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
ws_regex_matches(const ws_regex_t *re, const char *subj)
{
    return ws_regex_matches_length(re, subj, -1);
}


bool
ws_regex_matches_length(const ws_regex_t *re,
                        const char *subj, ssize_t subj_length)
{
    bool matched;
    pcre2_match_data *match_data;

    ws_return_val_if_null(re, FALSE);
    ws_return_val_if_null(subj, FALSE);

    /* We don't use the matched substring but pcre2_match requires
     * at least one pair of offsets. */
    match_data = pcre2_match_data_create(1, NULL);
    matched = match_pcre2(re->code, subj, subj_length, match_data);
    pcre2_match_data_free(match_data);
    return matched;
}


bool
ws_regex_matches_pos(const ws_regex_t *re,
                        const char *subj, ssize_t subj_length,
                        size_t pos_vect[2])
{
    bool matched;
    pcre2_match_data *match_data;

    ws_return_val_if_null(re, FALSE);
    ws_return_val_if_null(subj, FALSE);

    match_data = pcre2_match_data_create(1, NULL);
    matched = match_pcre2(re->code, subj, subj_length, match_data);
    if (matched && pos_vect) {
        PCRE2_SIZE *ovect = pcre2_get_ovector_pointer(match_data);
        pos_vect[0] = ovect[0];
        pos_vect[1] = ovect[1];
    }
    pcre2_match_data_free(match_data);
    return matched;
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
