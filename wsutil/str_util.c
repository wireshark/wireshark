/* str_util.c
 * String utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include "config.h"
#include "str_util.h"

#include <string.h>

#include <wsutil/to_str.h>

gchar *
wmem_strconcat(wmem_allocator_t *allocator, const gchar *first, ...)
{
    gsize   len;
    va_list args;
    gchar   *s;
    gchar   *concat;
    gchar   *ptr;

    if (!first)
        return NULL;

    len = 1 + strlen(first);
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        len += strlen(s);
    }
    va_end(args);

    ptr = concat = (gchar *)wmem_alloc(allocator, len);

    ptr = g_stpcpy(ptr, first);
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        ptr = g_stpcpy(ptr, s);
    }
    va_end(args);

    return concat;
}

gchar *
wmem_strjoin(wmem_allocator_t *allocator,
             const gchar *separator, const gchar *first, ...)
{
    gsize   len;
    va_list args;
    gsize separator_len;
    gchar   *s;
    gchar   *concat;
    gchar   *ptr;

    if (!first)
        return NULL;

    if (separator == NULL) {
        separator = "";
    }

    separator_len = strlen (separator);

    len = 1 + strlen(first); /* + 1 for null byte */
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        len += (separator_len + strlen(s));
    }
    va_end(args);

    ptr = concat = (gchar *)wmem_alloc(allocator, len);
    ptr = g_stpcpy(ptr, first);
    va_start(args, first);
    while ((s = va_arg(args, gchar*))) {
        ptr = g_stpcpy(ptr, separator);
        ptr = g_stpcpy(ptr, s);
    }
    va_end(args);

    return concat;

}

gchar *
wmem_strjoinv(wmem_allocator_t *allocator,
              const gchar *separator, gchar **str_array)
{
    gchar *string = NULL;

    if (!str_array)
        return NULL;

    if (separator == NULL) {
        separator = "";
    }

    if (str_array[0]) {
        gint i;
        gchar *ptr;
        gsize len, separator_len;

        separator_len = strlen(separator);

        /* Get first part of length. Plus one for null byte. */
        len = 1 + strlen(str_array[0]);
        /* Get the full length, including the separators. */
        for (i = 1; str_array[i] != NULL; i++) {
            len += separator_len;
            len += strlen(str_array[i]);
        }

        /* Allocate and build the string. */
        string = (gchar *)wmem_alloc(allocator, len);
        ptr = g_stpcpy(string, str_array[0]);
        for (i = 1; str_array[i] != NULL; i++) {
            ptr = g_stpcpy(ptr, separator);
            ptr = g_stpcpy(ptr, str_array[i]);
        }
    }

    return string;

}

gchar **
wmem_strsplit(wmem_allocator_t *allocator, const gchar *src,
        const gchar *delimiter, int max_tokens)
{
    gchar *splitted;
    gchar *s;
    guint tokens;
    guint sep_len;
    guint i;
    gchar **vec;

    if (!src || !delimiter || !delimiter[0])
        return NULL;

    /* An empty string results in an empty vector. */
    if (!src[0]) {
        vec = wmem_new0(allocator, gchar *);
        return vec;
    }

    splitted = wmem_strdup(allocator, src);
    sep_len = (guint)strlen(delimiter);

    if (max_tokens < 1)
        max_tokens = INT_MAX;

    /* Calculate the number of fields. */
    s = splitted;
    tokens = 1;
    while (tokens < (guint)max_tokens && (s = strstr(s, delimiter))) {
        s += sep_len;
        tokens++;
    }

    vec = wmem_alloc_array(allocator, gchar *, tokens + 1);

    /* Populate the array of string tokens. */
    s = splitted;
    vec[0] = s;
    tokens = 1;
    while (tokens < (guint)max_tokens && (s = strstr(s, delimiter))) {
        for (i = 0; i < sep_len; i++)
            s[i] = '\0';
        s += sep_len;
        vec[tokens] = s;
        tokens++;

    }

    vec[tokens] = NULL;

    return vec;
}

/*
 * wmem_ascii_strdown:
 * based on g_ascii_strdown.
 */
gchar*
wmem_ascii_strdown(wmem_allocator_t *allocator, const gchar *str, gssize len)
{
    gchar *result, *s;

    g_return_val_if_fail (str != NULL, NULL);

    if (len < 0)
        len = strlen (str);

    result = wmem_strndup(allocator, str, len);
    for (s = result; *s; s++)
        *s = g_ascii_tolower (*s);

    return result;
}

int
ws_xton(char ch)
{
    switch (ch) {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a':  case 'A': return 10;
        case 'b':  case 'B': return 11;
        case 'c':  case 'C': return 12;
        case 'd':  case 'D': return 13;
        case 'e':  case 'E': return 14;
        case 'f':  case 'F': return 15;
        default: return -1;
    }
}

/* Convert all ASCII letters to lower case, in place. */
gchar *
ascii_strdown_inplace(gchar *str)
{
    gchar *s;

    for (s = str; *s; s++)
        /* What 'g_ascii_tolower (gchar c)' does, this should be slightly more efficient */
        *s = g_ascii_isupper (*s) ? *s - 'A' + 'a' : *s;

    return (str);
}

/* Convert all ASCII letters to upper case, in place. */
gchar *
ascii_strup_inplace(gchar *str)
{
    gchar *s;

    for (s = str; *s; s++)
        /* What 'g_ascii_toupper (gchar c)' does, this should be slightly more efficient */
        *s = g_ascii_islower (*s) ? *s - 'a' + 'A' : *s;

    return (str);
}

/* Check if an entire string is printable. */
gboolean
isprint_string(const gchar *str)
{
    guint pos;

    /* Loop until we reach the end of the string (a null) */
    for(pos = 0; str[pos] != '\0'; pos++){
        if(!g_ascii_isprint(str[pos])){
            /* The string contains a non-printable character */
            return FALSE;
        }
    }

    /* The string contains only printable characters */
    return TRUE;
}

/* Check if an entire UTF-8 string is printable. */
gboolean
isprint_utf8_string(const gchar *str, guint length)
{
    const char *c;

    if (!g_utf8_validate (str, length, NULL)) {
        return FALSE;
    }

    for (c = str; *c; c = g_utf8_next_char(c)) {
        if (!g_unichar_isprint(g_utf8_get_char(c))) {
            return FALSE;
        }
    }

    return TRUE;
}

/* Check if an entire string is digits. */
gboolean
isdigit_string(const guchar *str)
{
    guint pos;

    /* Loop until we reach the end of the string (a null) */
    for(pos = 0; str[pos] != '\0'; pos++){
        if(!g_ascii_isdigit(str[pos])){
            /* The string contains a non-digit character */
            return FALSE;
        }
    }

    /* The string contains only digits */
    return TRUE;
}

/* Return the first occurrence of needle in haystack.
 * If not found, return NULL.
 * If either haystack or needle has 0 length, return NULL.*/
const guint8 *
ws_memmem(const void *_haystack, size_t haystack_len,
                const void *_needle, size_t needle_len)
{
#ifdef HAVE_MEMMEM
    return memmem(_haystack, haystack_len, _needle, needle_len);
#else
    /* Algorithm copied from GNU's glibc 2.3.2 memmem() under LGPL 2.1+ */
    const guint8 *haystack = _haystack;
    const guint8 *needle = _needle;
    const guint8 *begin;
    const guint8 *const last_possible = haystack + haystack_len - needle_len;

    if (needle_len == 0) {
        return NULL;
    }

    if (needle_len > haystack_len) {
        return NULL;
    }

    for (begin = haystack ; begin <= last_possible; ++begin) {
        if (begin[0] == needle[0] &&
                !memcmp(&begin[1], needle + 1,
                    needle_len - 1)) {
            return begin;
        }
    }

    return NULL;
#endif /* HAVE_MEMMEM */
}

const char *
ws_strcasestr(const char *haystack, const char *needle)
{
#ifdef HAVE_STRCASESTR
    return strcasestr(haystack, needle);
#else
    gsize hlen = strlen(haystack);
    gsize nlen = strlen(needle);

    while (hlen-- >= nlen) {
        if (!g_ascii_strncasecmp(haystack, needle, nlen))
            return haystack;
        haystack++;
    }
    return NULL;
#endif /* HAVE_STRCASESTR */
}

#define FORMAT_SIZE_UNIT_MASK 0x00ff
#define FORMAT_SIZE_PFX_MASK 0xff00

static const char *thousands_grouping_fmt = NULL;

DIAG_OFF(format)
static void test_printf_thousands_grouping(void) {
    /* test whether wmem_strbuf works with "'" flag character */
    wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);
    wmem_strbuf_append_printf(buf, "%'d", 22);
    if (g_strcmp0(wmem_strbuf_get_str(buf), "22") == 0) {
        thousands_grouping_fmt = "%'"PRId64;
    } else {
        /* Don't use */
        thousands_grouping_fmt = "%"PRId64;
    }
    wmem_strbuf_destroy(buf);
}
DIAG_ON(format)

/* Given a size, return its value in a human-readable format */
/* This doesn't handle fractional values. We might want to make size a double. */
char *
format_size_wmem(wmem_allocator_t *allocator, int64_t size,
                        format_size_units_e unit, uint16_t flags)
{
    wmem_strbuf_t *human_str = wmem_strbuf_new(allocator, NULL);
    int power = 1000;
    int pfx_off = 0;
    gboolean is_small = FALSE;
    static const gchar *prefix[] = {" T", " G", " M", " k", " Ti", " Gi", " Mi", " Ki"};
    gchar *ret_val;

    if (thousands_grouping_fmt == NULL)
        test_printf_thousands_grouping();

    if (flags & FORMAT_SIZE_PREFIX_IEC) {
        pfx_off = 4;
        power = 1024;
    }

    if (size / power / power / power / power >= 10) {
        wmem_strbuf_append_printf(human_str, thousands_grouping_fmt, size / power / power / power / power);
        wmem_strbuf_append(human_str, prefix[pfx_off]);
    } else if (size / power / power / power >= 10) {
        wmem_strbuf_append_printf(human_str, thousands_grouping_fmt, size / power / power / power);
        wmem_strbuf_append(human_str, prefix[pfx_off+1]);
    } else if (size / power / power >= 10) {
        wmem_strbuf_append_printf(human_str, thousands_grouping_fmt, size / power / power);
        wmem_strbuf_append(human_str, prefix[pfx_off+2]);
    } else if (size / power >= 10) {
        wmem_strbuf_append_printf(human_str, thousands_grouping_fmt, size / power);
        wmem_strbuf_append(human_str, prefix[pfx_off+3]);
    } else {
        wmem_strbuf_append_printf(human_str, thousands_grouping_fmt, size);
        is_small = TRUE;
    }

    switch (unit) {
        case FORMAT_SIZE_UNIT_NONE:
            break;
        case FORMAT_SIZE_UNIT_BYTES:
            wmem_strbuf_append(human_str, is_small ? " bytes" : "B");
            break;
        case FORMAT_SIZE_UNIT_BITS:
            wmem_strbuf_append(human_str, is_small ? " bits" : "b");
            break;
        case FORMAT_SIZE_UNIT_BITS_S:
            wmem_strbuf_append(human_str, is_small ? " bits/s" : "bps");
            break;
        case FORMAT_SIZE_UNIT_BYTES_S:
            wmem_strbuf_append(human_str, is_small ? " bytes/s" : "Bps");
            break;
        case FORMAT_SIZE_UNIT_PACKETS:
            wmem_strbuf_append(human_str, is_small ? " packets" : "packets");
            break;
        case FORMAT_SIZE_UNIT_PACKETS_S:
            wmem_strbuf_append(human_str, is_small ? " packets/s" : "packets/s");
            break;
        default:
            ws_assert_not_reached();
    }

    ret_val = wmem_strbuf_finalize(human_str);
    return g_strchomp(ret_val);
}

gchar
printable_char_or_period(gchar c)
{
    return g_ascii_isprint(c) ? c : '.';
}

static inline char
escape_char(char c)
{
    /*
     * Backslashes and double-quotes must
     * be escaped. Whitespace is also escaped.
     */
    switch (c) {
        case '\a': return 'a';
        case '\b': return 'b';
        case '\f': return 'f';
        case '\n': return 'n';
        case '\r': return 'r';
        case '\t': return 't';
        case '\v': return 'v';
        case '"':
        case '\\':
            return c;
    }
    return 0;
}

static size_t
escape_string_len(const char *string, bool add_quotes)
{
    const char *p;
    gchar c;
    size_t repr_len;

    repr_len = 0;
    for (p = string; (c = *p) != '\0'; p++) {
        if (escape_char(c) != 0) {
            repr_len += 2;
        }
        else {
            repr_len++;
        }
    }
    if (add_quotes)
        repr_len += 2; /* string plus leading and trailing quotes */
    return repr_len;
}

/*
 * This is used by the display filter engine and must be compatible
 * with display filter syntax.
 */
char *
ws_escape_string(wmem_allocator_t *alloc, const char *string, bool add_quotes)
{
    const char *p;
    char c, r;
    char *buf, *bufp;

    bufp = buf = wmem_alloc(alloc, escape_string_len(string, add_quotes) + 1);
    if (add_quotes)
        *bufp++ = '"';
    for (p = string; (c = *p) != '\0'; p++) {
        if ((r = escape_char(c)) != 0) {
            *bufp++ = '\\';
            *bufp++ = r;
        }
        else {
            /* Other UTF-8 bytes are passed through. */
            *bufp++ = c;
        }
    }
    if (add_quotes)
        *bufp++ = '"';
    *bufp = '\0';
    return buf;
}

const char *
ws_strerrorname_r(int errnum, char *buf, size_t buf_size)
{
#ifdef HAVE_STRERRORNAME_NP
    const char *errstr = strerrorname_np(errnum);
    if (errstr != NULL) {
        (void)g_strlcpy(buf, errstr, buf_size);
        return buf;
    }
#endif
    snprintf(buf, buf_size, "Errno(%d)", errnum);
    return buf;
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
