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
#include <locale.h>
#include <math.h>

#include <ws_codepoints.h>

#include <wsutil/to_str.h>


static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

char *
wmem_strconcat(wmem_allocator_t *allocator, const char *first, ...)
{
    size_t  len;
    va_list args;
    char    *s;
    char    *concat;
    char    *ptr;

    if (!first)
        return NULL;

    len = 1 + strlen(first);
    va_start(args, first);
    while ((s = va_arg(args, char*))) {
        len += strlen(s);
    }
    va_end(args);

    ptr = concat = (char *)wmem_alloc(allocator, len);

    ptr = g_stpcpy(ptr, first);
    va_start(args, first);
    while ((s = va_arg(args, char*))) {
        ptr = g_stpcpy(ptr, s);
    }
    va_end(args);

    return concat;
}

char *
wmem_strjoin(wmem_allocator_t *allocator,
             const char *separator, const char *first, ...)
{
    size_t  len;
    va_list args;
    size_t separator_len;
    char    *s;
    char    *concat;
    char    *ptr;

    if (!first)
        return NULL;

    if (separator == NULL) {
        separator = "";
    }

    separator_len = strlen (separator);

    len = 1 + strlen(first); /* + 1 for null byte */
    va_start(args, first);
    while ((s = va_arg(args, char*))) {
        len += (separator_len + strlen(s));
    }
    va_end(args);

    ptr = concat = (char *)wmem_alloc(allocator, len);
    ptr = g_stpcpy(ptr, first);
    va_start(args, first);
    while ((s = va_arg(args, char*))) {
        ptr = g_stpcpy(ptr, separator);
        ptr = g_stpcpy(ptr, s);
    }
    va_end(args);

    return concat;

}

char *
wmem_strjoinv(wmem_allocator_t *allocator,
              const char *separator, char **str_array)
{
    char *string = NULL;

    ws_return_val_if(!str_array, NULL);

    if (separator == NULL) {
        separator = "";
    }

    if (str_array[0]) {
        int i;
        char *ptr;
        size_t len, separator_len;

        separator_len = strlen(separator);

        /* Get first part of length. Plus one for null byte. */
        len = 1 + strlen(str_array[0]);
        /* Get the full length, including the separators. */
        for (i = 1; str_array[i] != NULL; i++) {
            len += separator_len;
            len += strlen(str_array[i]);
        }

        /* Allocate and build the string. */
        string = (char *)wmem_alloc(allocator, len);
        ptr = g_stpcpy(string, str_array[0]);
        for (i = 1; str_array[i] != NULL; i++) {
            ptr = g_stpcpy(ptr, separator);
            ptr = g_stpcpy(ptr, str_array[i]);
        }
    } else {
        string = wmem_strdup(allocator, "");
    }

    return string;

}

char **
wmem_strsplit(wmem_allocator_t *allocator, const char *src,
        const char *delimiter, int max_tokens)
{
    char *splitted;
    char *s;
    unsigned tokens;
    unsigned sep_len;
    unsigned i;
    char **vec;

    if (!src || !delimiter || !delimiter[0])
        return NULL;

    /* An empty string results in an empty vector. */
    if (!src[0]) {
        vec = wmem_new0(allocator, char *);
        return vec;
    }

    splitted = wmem_strdup(allocator, src);
    sep_len = (unsigned)strlen(delimiter);

    if (max_tokens < 1)
        max_tokens = INT_MAX;

    /* Calculate the number of fields. */
    s = splitted;
    tokens = 1;
    while (tokens < (unsigned)max_tokens && (s = strstr(s, delimiter))) {
        s += sep_len;
        tokens++;
    }

    vec = wmem_alloc_array(allocator, char *, tokens + 1);

    /* Populate the array of string tokens. */
    s = splitted;
    vec[0] = s;
    tokens = 1;
    while (tokens < (unsigned)max_tokens && (s = strstr(s, delimiter))) {
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
char*
wmem_ascii_strdown(wmem_allocator_t *allocator, const char *str, ssize_t len)
{
    char *result, *s;

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
char *
ascii_strdown_inplace(char *str)
{
    char *s;

    for (s = str; *s; s++)
        /* What 'g_ascii_tolower (char c)' does, this should be slightly more efficient */
        *s = g_ascii_isupper (*s) ? *s - 'A' + 'a' : *s;

    return (str);
}

/* Convert all ASCII letters to upper case, in place. */
char *
ascii_strup_inplace(char *str)
{
    char *s;

    for (s = str; *s; s++)
        /* What 'g_ascii_toupper (char c)' does, this should be slightly more efficient */
        *s = g_ascii_islower (*s) ? *s - 'a' + 'A' : *s;

    return (str);
}

/* Check if an entire string is printable. */
bool
isprint_string(const char *str)
{
    unsigned pos;

    /* Loop until we reach the end of the string (a null) */
    for(pos = 0; str[pos] != '\0'; pos++){
        if(!g_ascii_isprint(str[pos])){
            /* The string contains a non-printable character */
            return false;
        }
    }

    /* The string contains only printable characters */
    return true;
}

/* Check if an entire UTF-8 string is printable. */
bool
isprint_utf8_string(const char *str, const unsigned length)
{
    const char *strend = str + length;

    if (!g_utf8_validate(str, length, NULL)) {
        return false;
    }

    while (str < strend) {
        /* This returns false for G_UNICODE_CONTROL | G_UNICODE_FORMAT |
         * G_UNICODE_UNASSIGNED | G_UNICODE_SURROGATE
         * XXX: Could it be ok to have certain format characters, e.g.
         * U+00AD SOFT HYPHEN? If so, format_text() should be changed too.
         */
        if (!g_unichar_isprint(g_utf8_get_char(str))) {
            return false;
        }
        str = g_utf8_next_char(str);
    }

    return true;
}

/* Check if an entire string is digits. */
bool
isdigit_string(const unsigned char *str)
{
    unsigned pos;

    /* Loop until we reach the end of the string (a null) */
    for(pos = 0; str[pos] != '\0'; pos++){
        if(!g_ascii_isdigit(str[pos])){
            /* The string contains a non-digit character */
            return false;
        }
    }

    /* The string contains only digits */
    return true;
}

const char *
ws_ascii_strcasestr(const char *haystack, const char *needle)
{
    /* Do not use strcasestr() here, even if a system has it, as it is
     * locale-dependent (and has different results for e.g. Turkic languages.)
     * FreeBSD, NetBSD, macOS have a strcasestr_l() that could be used.
     */
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);

    while (hlen-- >= nlen) {
        if (!g_ascii_strncasecmp(haystack, needle, nlen))
            return haystack;
        haystack++;
    }
    return NULL;
}

/* Return the last occurrence of ch in the n bytes of haystack.
 * If not found or n is 0, return NULL. */
const uint8_t *
ws_memrchr(const void *_haystack, int ch, size_t n)
{
#ifdef HAVE_MEMRCHR
    return memrchr(_haystack, ch, n);
#else
    /* A generic implementation. This could be optimized considerably,
     * e.g. by fetching a word at a time.
     */
    if (n == 0) {
        return NULL;
    }
    const uint8_t *haystack = _haystack;
    const uint8_t *p;
    uint8_t c = (uint8_t)ch;

    const uint8_t *const end = haystack + n - 1;

    for (p = end; p >= haystack; --p) {
        if (*p == c) {
            return p;
        }
    }

    return NULL;
#endif /* HAVE_MEMRCHR */
}

#define FORMAT_SIZE_UNIT_MASK 0x00ff
#define FORMAT_SIZE_PFX_MASK 0xff00

static const char *thousands_grouping_fmt;
static const char *thousands_grouping_fmt_flt;

DIAG_OFF(format)
static void test_printf_thousands_grouping(void) {
    /* test whether wmem_strbuf works with "'" flag character */
    wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);
    wmem_strbuf_append_printf(buf, "%'d", 22);
    if (g_strcmp0(wmem_strbuf_get_str(buf), "22") == 0) {
        thousands_grouping_fmt = "%'"PRId64;
        thousands_grouping_fmt_flt = "%'.*f";
    } else {
        /* Don't use */
        thousands_grouping_fmt = "%"PRId64;
        thousands_grouping_fmt_flt = "%.*f";
    }
    wmem_strbuf_destroy(buf);
}
DIAG_ON(format)

static const char* decimal_point = NULL;

static void truncate_numeric_strbuf(wmem_strbuf_t *strbuf, int n) {

    const char *s = wmem_strbuf_get_str(strbuf);
    char *p;
    int count;

    if (decimal_point == NULL) {
        decimal_point = localeconv()->decimal_point;
    }

    p = strchr(s, decimal_point[0]);
    if (p != NULL) {
        count = n;
        while (count >= 0) {
            count--;
            if (*p == '\0')
                break;
            p++;
        }

        p--;
        while (*p == '0') {
            p--;
        }

        if (*p != decimal_point[0]) {
            p++;
        }
        wmem_strbuf_truncate(strbuf, p - s);
    }
}

/* Given a floating point value, return it in a human-readable format,
 * using units with metric prefixes (falling back to scientific notation
 * with the base units if outside the range.)
 */
char *
format_units(wmem_allocator_t *allocator, double size,
             format_size_units_e unit, uint16_t flags,
             int precision)
{
    wmem_strbuf_t *human_str = wmem_strbuf_new(allocator, NULL);
    double power = 1000.0;
    int pfx_off = 6;
    bool is_small = false;
    /* is_small is when to use the longer, spelled out unit.
     * We use it for inf, NaN, 0, and unprefixed small values,
     * but not for unprefixed values using scientific notation
     * the value is outside the supported prefix range.
     */
    bool scientific = false;
    double abs_size = fabs(size);
    int exponent = 0;
    static const char * const si_prefix[] = {" a", " f", " p", " n", " μ", " m", " ", " k", " M", " G", " T", " P", " E"};
    static const char * const iec_prefix[] = {" ", " Ki", " Mi", " Gi", " Ti", " Pi", " Ei"};
    const char * const *prefix = si_prefix;
    int max_exp = (int)G_N_ELEMENTS(si_prefix) - 1;

    char *ret_val;

    if (thousands_grouping_fmt == NULL)
        test_printf_thousands_grouping();

    if (flags & FORMAT_SIZE_PREFIX_IEC) {
        prefix = iec_prefix;
        max_exp = (int)G_N_ELEMENTS(iec_prefix) - 1;
        power = 1024.0;
    }

    if (isfinite(size) && size != 0.0) {

        double comp = precision == 0 ? 10.0 : 1.0;

        /* For precision 0, use the range [10, 10*power) because only
         * one significant digit is not as useful. This is what format_size
         * does for integers. ("ls -h" uses one digit after the decimal
         * point only for the [1, 10) range, g_format_size() always displays
         * tenths.) Prefer non-prefixed units for the range [1,10), though.
         *
         * We have a limited number of units to check, so this (which
         * can be unrolled) is presumably faster than log + floor + pow/exp
         */
        if (abs_size < 1.0) {
            while (abs_size < comp) {
                abs_size *= power;
                exponent--;
                if ((exponent + pfx_off) < 0) {
                    scientific = true;
                    break;
                }
            }
        } else {
            while (abs_size >= comp*power) {
                abs_size *= 1/power;
                exponent++;
                if ((exponent + pfx_off) > max_exp) {
                    scientific = true;
                    break;
                }
            }
        }
    }

    if (scientific) {
        wmem_strbuf_append_printf(human_str, "%.*g", precision + 1, size);
        exponent = 0;
    } else {
        if (exponent == 0) {
            is_small = true;
        }
        size = copysign(abs_size, size);
        // Truncate trailing zeros, but do it this way because we know
        // we don't want scientific notation, and we don't want %g to
        // switch to that if precision is small. (We could always use
        // %g when precision is large.)
        wmem_strbuf_append_printf(human_str, thousands_grouping_fmt_flt, precision, size);
        truncate_numeric_strbuf(human_str, precision);
        // XXX - when rounding to a certain precision, printf might
        // round up to "power" from something like 999.99999995, which
        // looks a little odd on a graph when transitioning from 1,000 bytes
        // (for values just under 1 kB) to 1 kB (for values 1 kB and larger.)
        // Due to edge cases in binary fp representation and how printf might
        // round things, the right way to handle it is taking the printf output
        // and comparing it to "1000" and "1024" and adjusting the exponent
        // if so - though we need to compare to the version with the thousands
        // separator if we have that (which makes it harder to use strnatcmp
        // as is.)
    }

    if ((size_t)(pfx_off + exponent) < G_N_ELEMENTS(si_prefix)) {
        wmem_strbuf_append(human_str, prefix[pfx_off+exponent]);
    }

    switch (unit) {
        case FORMAT_SIZE_UNIT_NONE:
            break;
        case FORMAT_SIZE_UNIT_BYTES:
            wmem_strbuf_append(human_str, is_small ? "bytes" : "B");
            break;
        case FORMAT_SIZE_UNIT_BITS:
            wmem_strbuf_append(human_str, is_small ? "bits" : "b");
            break;
        case FORMAT_SIZE_UNIT_BITS_S:
            wmem_strbuf_append(human_str, is_small ? "bits/s" : "bps");
            break;
        case FORMAT_SIZE_UNIT_BYTES_S:
            wmem_strbuf_append(human_str, is_small ? "bytes/s" : "Bps");
            break;
        case FORMAT_SIZE_UNIT_PACKETS:
            wmem_strbuf_append(human_str, is_small ? "packets" : "packets");
            break;
        case FORMAT_SIZE_UNIT_PACKETS_S:
            wmem_strbuf_append(human_str, is_small ? "packets/s" : "packets/s");
            break;
        case FORMAT_SIZE_UNIT_EVENTS:
            wmem_strbuf_append(human_str, is_small ? "events" : "events");
            break;
        case FORMAT_SIZE_UNIT_EVENTS_S:
            wmem_strbuf_append(human_str, is_small ? "events/s" : "events/s");
            break;
        case FORMAT_SIZE_UNIT_FIELDS:
            wmem_strbuf_append(human_str, is_small ? "fields" : "fields");
            break;
        case FORMAT_SIZE_UNIT_SECONDS:
            wmem_strbuf_append(human_str, is_small ? "seconds" : "s");
            break;
        case FORMAT_SIZE_UNIT_ERLANGS:
            wmem_strbuf_append(human_str, is_small ? "erlangs" : "E");
            break;
        default:
            ws_assert_not_reached();
    }

    ret_val = wmem_strbuf_finalize(human_str);
    /* Convention is a space between the value and the units. If we have
     * a prefix, the space is before the prefix. There are two possible
     * uses of FORMAT_SIZE_UNIT_NONE:
     * 1. Add a unit immediately after the string returned. In this case,
     *    we would want the string to end with a space if there's no prefix.
     * 2. The unit appears somewhere else, e.g. in a legend, header, or
     *    different column. In this case, we don't want the string to end
     *    with a space if there's no prefix.
     * chomping the string here, as we've traditionally done, optimizes for
     * the latter case but makes the former case harder.
     * Perhaps the right approach is to distinguish the cases with a new
     * enum value.
     */
    return g_strchomp(ret_val);
}

/* Given a size, return its value in a human-readable format */
/* This doesn't handle fractional values. We might want to just
 * call the version with the double and precision 0 (possibly
 * slower due to the use of floating point math, but do we care?)
 */
char *
format_size_wmem(wmem_allocator_t *allocator, int64_t size,
                        format_size_units_e unit, uint16_t flags)
{
    wmem_strbuf_t *human_str = wmem_strbuf_new(allocator, NULL);
    int power = 1000;
    int pfx_off = 0;
    bool is_small = false;
    static const char *prefix[] = {" T", " G", " M", " k", " Ti", " Gi", " Mi", " Ki"};
    char *ret_val;

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
        is_small = true;
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
        case FORMAT_SIZE_UNIT_FIELDS:
            wmem_strbuf_append(human_str, is_small ? " fields" : "fields");
            break;
        /* These aren't that practical to use with integers, but
         * perhaps better than asserting.
         */
        case FORMAT_SIZE_UNIT_SECONDS:
            wmem_strbuf_append(human_str, is_small ? " seconds" : "s");
            break;
        case FORMAT_SIZE_UNIT_ERLANGS:
            wmem_strbuf_append(human_str, is_small ? " erlangs" : "E");
            break;
        default:
            ws_assert_not_reached();
    }

    ret_val = wmem_strbuf_finalize(human_str);
    return g_strchomp(ret_val);
}

char
printable_char_or_period(char c)
{
    return g_ascii_isprint(c) ? c : '.';
}

/*
 * This is used by the display filter engine and must be compatible
 * with display filter syntax.
 */
static inline bool
escape_char(char c, char *p)
{
    int r = -1;
    ws_assert(p);

    /*
     * backslashes and double-quotes must be escaped (double-quotes
     * are escaped by passing '"' as quote_char in escape_string_len)
     * whitespace is also escaped.
     */
    switch (c) {
        case '\a': r = 'a'; break;
        case '\b': r = 'b'; break;
        case '\f': r = 'f'; break;
        case '\n': r = 'n'; break;
        case '\r': r = 'r'; break;
        case '\t': r = 't'; break;
        case '\v': r = 'v'; break;
        case '\\': r = '\\'; break;
        case '\0': r = '0'; break;
    }

    if (r != -1) {
        *p = r;
        return true;
    }
    return false;
}

static inline bool
escape_null(char c, char *p)
{
    ws_assert(p);
    if (c == '\0') {
        *p = '0';
        return true;
    }
    return false;
}

static char *
escape_string_len(wmem_allocator_t *alloc, const char *string, ssize_t len,
                    bool (*escape_func)(char c, char *p), bool add_quotes,
                    char quote_char, bool double_quote)
{
    char c, r;
    wmem_strbuf_t *buf;
    size_t alloc_size;
    ssize_t i;

    if (len < 0)
        len = strlen(string);

    alloc_size = len;
    if (add_quotes)
        alloc_size += 2;

    buf = wmem_strbuf_new_sized(alloc, alloc_size);

    if (add_quotes && quote_char != '\0')
        wmem_strbuf_append_c(buf, quote_char);

    for (i = 0; i < len; i++) {
        c = string[i];
        if ((escape_func(c, &r))) {
            wmem_strbuf_append_c(buf, '\\');
            wmem_strbuf_append_c(buf, r);
        }
        else if (c == quote_char && quote_char != '\0') {
            /* If quoting, we must escape the quote_char somehow. */
            if (double_quote) {
                wmem_strbuf_append_c(buf, c);
                wmem_strbuf_append_c(buf, c);
            } else {
                wmem_strbuf_append_c(buf, '\\');
                wmem_strbuf_append_c(buf, c);
            }
        }
        else if (c == '\\' && quote_char != '\0' && !double_quote) {
            /* If quoting, and escaping the quote_char with a backslash,
             * then backslash must be escaped, even if escape_func doesn't. */
            wmem_strbuf_append_c(buf, '\\');
            wmem_strbuf_append_c(buf, '\\');
        }
        else {
            /* Other UTF-8 bytes are passed through. */
            wmem_strbuf_append_c(buf, c);
        }
    }

    if (add_quotes && quote_char != '\0')
        wmem_strbuf_append_c(buf, quote_char);

    return wmem_strbuf_finalize(buf);
}

char *
ws_escape_string_len(wmem_allocator_t *alloc, const char *string, ssize_t len, bool add_quotes)
{
    return escape_string_len(alloc, string, len, escape_char, add_quotes, '"', false);
}

char *
ws_escape_string(wmem_allocator_t *alloc, const char *string, bool add_quotes)
{
    return escape_string_len(alloc, string, -1, escape_char, add_quotes, '"', false);
}

char *ws_escape_null(wmem_allocator_t *alloc, const char *string, size_t len, bool add_quotes)
{
    /* XXX: The existing behavior (maintained) here is not to escape
     * backslashes even though NUL is escaped.
     */
    return escape_string_len(alloc, string, len, escape_null, add_quotes, add_quotes ? '"' : '\0', false);
}

char *ws_escape_csv(wmem_allocator_t *alloc, const char *string, bool add_quotes, char quote_char, bool double_quote, bool escape_whitespace)
{
    if (escape_whitespace)
        return escape_string_len(alloc, string, -1, escape_char, add_quotes, quote_char, double_quote);
    else
        return escape_string_len(alloc, string, -1, escape_null, add_quotes, quote_char, double_quote);
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

char *
ws_strdup_underline(wmem_allocator_t *allocator, long offset, size_t len)
{
    if (offset < 0)
        return NULL;

    wmem_strbuf_t *buf = wmem_strbuf_new_sized(allocator, offset + len);

    for (int i = 0; i < offset; i++) {
        wmem_strbuf_append_c(buf, ' ');
    }
    wmem_strbuf_append_c(buf, '^');

    for (size_t l = len; l > 1; l--) {
        wmem_strbuf_append_c(buf, '~');
    }

    return wmem_strbuf_finalize(buf);
}

#define    INITIAL_FMTBUF_SIZE    128

/*
 * Declare, and initialize, the variables used for an output buffer.
 */
#define FMTBUF_VARS \
    char *fmtbuf = (char*)wmem_alloc(allocator, INITIAL_FMTBUF_SIZE); \
    unsigned fmtbuf_len = INITIAL_FMTBUF_SIZE; \
    unsigned column = 0

/*
 * Expand the buffer to be large enough to add nbytes bytes, plus a
 * terminating '\0'.
 */
#define FMTBUF_EXPAND(nbytes) \
    /* \
     * Is there enough room for those bytes and also enough room for \
     * a terminating '\0'? \
     */ \
    if (column+(nbytes+1) >= fmtbuf_len) { \
        /* \
         * Double the buffer's size if it's not big enough. \
         * The size of the buffer starts at 128, so doubling its size \
         * adds at least another 128 bytes, which is more than enough \
         * for one more character plus a terminating '\0'. \
         */ \
        fmtbuf_len *= 2; \
        fmtbuf = (char *)wmem_realloc(allocator, fmtbuf, fmtbuf_len); \
    }

/*
 * Put a byte into the buffer; space must have been ensured for it.
 */
#define FMTBUF_PUTCHAR(b) \
    fmtbuf[column] = (b); \
    column++

/*
 * Add the one-byte argument, as an octal escape sequence, to the end
 * of the buffer.
 */
#define FMTBUF_PUTBYTE_OCTAL(b) \
    FMTBUF_PUTCHAR((((b)>>6)&03) + '0'); \
    FMTBUF_PUTCHAR((((b)>>3)&07) + '0'); \
    FMTBUF_PUTCHAR((((b)>>0)&07) + '0')

/*
 * Add the one-byte argument, as a hex escape sequence, to the end
 * of the buffer.
 */
#define FMTBUF_PUTBYTE_HEX(b) \
    FMTBUF_PUTCHAR('\\'); \
    FMTBUF_PUTCHAR('x'); \
    FMTBUF_PUTCHAR(hex[((b) >> 4) & 0xF]); \
    FMTBUF_PUTCHAR(hex[((b) >> 0) & 0xF])

/*
 * Put the trailing '\0' at the end of the buffer.
 */
#define FMTBUF_ENDSTR \
    fmtbuf[column] = '\0'

static char *
format_text_internal(wmem_allocator_t *allocator,
                        const unsigned char *string, size_t len,
                        bool replace_space)
{
    FMTBUF_VARS;
    const unsigned char *stringend = string + len;
    unsigned char c;

    while (string < stringend) {
        /*
         * Get the first byte of this character.
         */
        c = *string++;
        if (g_ascii_isprint(c)) {
            /*
             * Printable ASCII, so not part of a multi-byte UTF-8 sequence.
             * Make sure there's enough room for one more byte, and add
             * the character.
             */
            FMTBUF_EXPAND(1);
            FMTBUF_PUTCHAR(c);
        } else if (replace_space && g_ascii_isspace(c)) {
            /*
             * ASCII, so not part of a multi-byte UTF-8 sequence, but
             * not printable, but is a space character; show it as a
             * blank.
             *
             * Make sure there's enough room for one more byte, and add
             * the blank.
             */
            FMTBUF_EXPAND(1);
            FMTBUF_PUTCHAR(' ');
        } else if (c < 128) {
            /*
             * ASCII, so not part of a multi-byte UTF-8 sequence, but not
             * printable.
             *
             * That requires a minimum of 2 bytes, one for the backslash
             * and one for a letter, so make sure we have enough room
             * for that, plus a trailing '\0'.
             */
            FMTBUF_EXPAND(2);
            FMTBUF_PUTCHAR('\\');
            switch (c) {

                case '\a':
                    FMTBUF_PUTCHAR('a');
                    break;

                case '\b':
                    FMTBUF_PUTCHAR('b'); /* BS */
                    break;

                case '\f':
                    FMTBUF_PUTCHAR('f'); /* FF */
                    break;

                case '\n':
                    FMTBUF_PUTCHAR('n'); /* NL */
                    break;

                case '\r':
                    FMTBUF_PUTCHAR('r'); /* CR */
                    break;

                case '\t':
                    FMTBUF_PUTCHAR('t'); /* tab */
                    break;

                case '\v':
                    FMTBUF_PUTCHAR('v');
                    break;

                default:
                    /*
                     * We've already put the backslash, but this
                     * will put 3 more characters for the octal
                     * number; make sure we have enough room for
                     * that, plus the trailing '\0'.
                     */
                    FMTBUF_EXPAND(3);
                    FMTBUF_PUTBYTE_OCTAL(c);
                    break;
            }
        } else {
            /*
             * We've fetched the first byte of a multi-byte UTF-8
             * sequence into c.
             */
            int utf8_len;
            unsigned char mask;
            gunichar uc;
            unsigned char first;

            if ((c & 0xe0) == 0xc0) {
                /* Starts a 2-byte UTF-8 sequence; 1 byte left */
                utf8_len = 1;
                mask = 0x1f;
            } else if ((c & 0xf0) == 0xe0) {
                /* Starts a 3-byte UTF-8 sequence; 2 bytes left */
                utf8_len = 2;
                mask = 0x0f;
            } else if ((c & 0xf8) == 0xf0) {
                /* Starts a 4-byte UTF-8 sequence; 3 bytes left */
                utf8_len = 3;
                mask = 0x07;
            } else if ((c & 0xfc) == 0xf8) {
                /* Starts an old-style 5-byte UTF-8 sequence; 4 bytes left */
                utf8_len = 4;
                mask = 0x03;
            } else if ((c & 0xfe) == 0xfc) {
                /* Starts an old-style 6-byte UTF-8 sequence; 5 bytes left */
                utf8_len = 5;
                mask = 0x01;
            } else {
                /* 0xfe or 0xff or a continuation byte - not valid */
                utf8_len = -1;
            }
            if (utf8_len > 0) {
                /* Try to construct the Unicode character */
                uc = c & mask;
                for (int i = 0; i < utf8_len; i++) {
                    if (string >= stringend) {
                        /*
                         * Ran out of octets, so the character is
                         * incomplete.  Put in a REPLACEMENT CHARACTER
                         * instead, and then continue the loop, which
                         * will terminate.
                         */
                        uc = UNICODE_REPLACEMENT_CHARACTER;
                        break;
                    }
                    c = *string;
                    if ((c & 0xc0) != 0x80) {
                        /*
                         * Not valid UTF-8 continuation character; put in
                         * a replacement character, and then re-process
                         * this octet as the beginning of a new character.
                         */
                        uc = UNICODE_REPLACEMENT_CHARACTER;
                        break;
                    }
                    string++;
                    uc = (uc << 6) | (c & 0x3f);
                }

                /*
                 * If this isn't a valid Unicode character, put in
                 * a REPLACEMENT CHARACTER.
                 */
                if (!g_unichar_validate(uc))
                    uc = UNICODE_REPLACEMENT_CHARACTER;
            } else {
                /* 0xfe or 0xff; put it a REPLACEMENT CHARACTER */
                uc = UNICODE_REPLACEMENT_CHARACTER;
            }

            /*
             * OK, is it a printable Unicode character?
             */
            if (g_unichar_isprint(uc)) {
                /*
                 * Yes - put it into the string as UTF-8.
                 * This means that if it was an overlong
                 * encoding, this will put out the right
                 * sized encoding.
                 */
                if (uc < 0x80) {
                    first = 0;
                    utf8_len = 1;
                } else if (uc < 0x800) {
                    first = 0xc0;
                    utf8_len = 2;
                } else if (uc < 0x10000) {
                    first = 0xe0;
                    utf8_len = 3;
                } else if (uc < 0x200000) {
                    first = 0xf0;
                    utf8_len = 4;
                } else if (uc < 0x4000000) {
                    /*
                     * This should never happen, as Unicode doesn't
                     * go that high.
                     */
                    first = 0xf8;
                    utf8_len = 5;
                } else {
                    /*
                     * This should never happen, as Unicode doesn't
                     * go that high.
                     */
                    first = 0xfc;
                    utf8_len = 6;
                }
                FMTBUF_EXPAND(utf8_len);
                for (int i = utf8_len - 1; i > 0; i--) {
                    fmtbuf[column + i] = (uc & 0x3f) | 0x80;
                    uc >>= 6;
                }
                fmtbuf[column] = uc | first;
                column += utf8_len;
            } else if (replace_space && g_unichar_isspace(uc)) {
                /*
                 * Not printable, but is a space character; show it
                 * as a blank.
                 *
                 * Make sure there's enough room for one more byte,
                 * and add the blank.
                 */
                FMTBUF_EXPAND(1);
                FMTBUF_PUTCHAR(' ');
            } else if (c < 128) {
                /*
                 * ASCII, but not printable.
                 * Yes, this could happen with an overlong encoding.
                 *
                 * That requires a minimum of 2 bytes, one for the
                 * backslash and one for a letter, so make sure we
                 * have enough room for that, plus a trailing '\0'.
                 */
                FMTBUF_EXPAND(2);
                FMTBUF_PUTCHAR('\\');
                switch (c) {

                    case '\a':
                        FMTBUF_PUTCHAR('a');
                        break;

                    case '\b':
                        FMTBUF_PUTCHAR('b'); /* BS */
                        break;

                    case '\f':
                        FMTBUF_PUTCHAR('f'); /* FF */
                        break;

                    case '\n':
                        FMTBUF_PUTCHAR('n'); /* NL */
                        break;

                    case '\r':
                        FMTBUF_PUTCHAR('r'); /* CR */
                        break;

                    case '\t':
                        FMTBUF_PUTCHAR('t'); /* tab */
                        break;

                    case '\v':
                        FMTBUF_PUTCHAR('v');
                        break;

                    default:
                        /*
                         * We've already put the backslash, but this
                         * will put 3 more characters for the octal
                         * number; make sure we have enough room for
                         * that, plus the trailing '\0'.
                         */
                        FMTBUF_EXPAND(3);
                        FMTBUF_PUTBYTE_OCTAL(c);
                        break;
                }
            } else {
                /*
                 * Unicode, but not printable, and not ASCII;
                 * put it out as \uxxxx or \Uxxxxxxxx.
                 */
                if (uc <= 0xFFFF) {
                    FMTBUF_EXPAND(6);
                    FMTBUF_PUTCHAR('\\');
                    FMTBUF_PUTCHAR('u');
                    FMTBUF_PUTCHAR(hex[(uc >> 12) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 8) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 4) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 0) & 0xF]);
                } else {
                    FMTBUF_EXPAND(10);
                    FMTBUF_PUTCHAR('\\');
                    FMTBUF_PUTCHAR('U');
                    FMTBUF_PUTCHAR(hex[(uc >> 28) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 24) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 20) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 16) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 12) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 8) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 4) & 0xF]);
                    FMTBUF_PUTCHAR(hex[(uc >> 0) & 0xF]);
                }
            }
        }
    }

    FMTBUF_ENDSTR;

    return fmtbuf;
}

/*
 * Given a wmem scope, a not-necessarily-null-terminated string,
 * expected to be in UTF-8 but possibly containing invalid sequences
 * (as it may have come from packet data), and the length of the string,
 * generate a valid UTF-8 string from it, allocated in the specified
 * wmem scope, that:
 *
 *   shows printable Unicode characters as themselves;
 *
 *   shows non-printable ASCII characters as C-style escapes (octal
 *   if not one of the standard ones such as LF -> '\n');
 *
 *   shows non-printable Unicode-but-not-ASCII characters as
 *   their universal character names;
 *
 *   shows illegal UTF-8 sequences as a sequence of bytes represented
 *   as C-style hex escapes (XXX: Does not actually do this. Some illegal
 *   sequences, such as overlong encodings, the sequences reserved for
 *   UTF-16 surrogate halves (paired or unpaired), and values outside
 *   Unicode (i.e., the old sequences for code points above U+10FFFF)
 *   will be decoded in a permissive way. Other illegal sequences,
 *   such 0xFE and 0xFF and the presence of a continuation byte where
 *   not expected (or vice versa its absence), are replaced with
 *   REPLACEMENT CHARACTER.)
 *
 * and return a pointer to it.
 */
char *
format_text(wmem_allocator_t *allocator,
                        const char *string, size_t len)
{
    return format_text_internal(allocator, string, len, false);
}

/** Given a wmem scope and a null-terminated string, expected to be in
 *  UTF-8 but possibly containing invalid sequences (as it may have come
 *  from packet data), and the length of the string, generate a valid
 *  UTF-8 string from it, allocated in the specified wmem scope, that:
 *
 *   shows printable Unicode characters as themselves;
 *
 *   shows non-printable ASCII characters as C-style escapes (octal
 *   if not one of the standard ones such as LF -> '\n');
 *
 *   shows non-printable Unicode-but-not-ASCII characters as
 *   their universal character names;
 *
 *   shows illegal UTF-8 sequences as a sequence of bytes represented
 *   as C-style hex escapes;
 *
 *  and return a pointer to it.
 */
char *
format_text_string(wmem_allocator_t* allocator, const char *string)
{
    return format_text_internal(allocator, string, strlen(string), false);
}

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 */
char *
format_text_wsp(wmem_allocator_t* allocator, const char *string, size_t len)
{
    return format_text_internal(allocator, string, len, true);
}

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as the chr parameter passed, except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 *
 * This does *not* treat the input string as UTF-8.
 *
 * This is useful for displaying binary data that frequently but not always
 * contains text; otherwise the number of C escape codes makes it unreadable.
 */
char *
format_text_chr(wmem_allocator_t *allocator, const char *string, size_t len, char chr)
{
    wmem_strbuf_t *buf;

    buf = wmem_strbuf_new_sized(allocator, len + 1);
    for (const char *p = string; p < string + len; p++) {
        if (g_ascii_isprint(*p)) {
            wmem_strbuf_append_c(buf, *p);
        }
        else if (g_ascii_isspace(*p)) {
            wmem_strbuf_append_c(buf, ' ');
        }
        else {
            wmem_strbuf_append_c(buf, chr);
        }
    }
    return wmem_strbuf_finalize(buf);
}

char *
format_char(wmem_allocator_t *allocator, char c)
{
    char *buf;
    char r;

    if (g_ascii_isprint(c)) {
        buf = wmem_alloc_array(allocator, char, 2);
        buf[0] = c;
        buf[1] = '\0';
        return buf;
    }
    if (escape_char(c, &r)) {
        buf = wmem_alloc_array(allocator, char, 3);
        buf[0] = '\\';
        buf[1] = r;
        buf[2] = '\0';
        return buf;
    }
    buf = wmem_alloc_array(allocator, char, 5);
    buf[0] = '\\';
    buf[1] = 'x';
    buf[2] = hex[((uint8_t)c >> 4) & 0xF];
    buf[3] = hex[((uint8_t)c >> 0) & 0xF];
    buf[4] = '\0';
    return buf;
}

char*
ws_utf8_truncate(char *string, size_t len)
{
    char* last_char;

    /* Ensure that it is null terminated */
    string[len] = '\0';
    last_char = g_utf8_find_prev_char(string, string + len);
    if (last_char != NULL && g_utf8_get_char_validated(last_char, -1) == (gunichar)-2) {
        /* The last UTF-8 character was truncated into a partial sequence. */
        *last_char = '\0';
    }
    return string;
}

/* ASCII/EBCDIC conversion tables from
 * https://web.archive.org/web/20060813174742/http://www.room42.com/store/computer_center/code_tables.shtml
 */
#if 0
static const uint8_t ASCII_translate_EBCDIC [ 256 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, 0x4D,
    0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
    0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
    0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,
    0x7D, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xC0, 0x6A, 0xD0, 0xA1, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B
};

void
ASCII_to_EBCDIC(uint8_t *buf, unsigned bytes)
{
    unsigned i;
    uint8_t   *bufptr;

    bufptr = buf;

    for (i = 0; i < bytes; i++, bufptr++) {
        *bufptr = ASCII_translate_EBCDIC[*bufptr];
    }
}

uint8_t
ASCII_to_EBCDIC1(uint8_t c)
{
    return ASCII_translate_EBCDIC[c];
}
#endif

static const uint8_t EBCDIC_translate_ASCII [ 256 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x2E, 0x2E, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x2E, 0x3F,
    0x20, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
    0x26, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,
    0x2D, 0x2F, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x7C, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
    0x2E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
    0x71, 0x72, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7A, 0x2E, 0x2E, 0x2E, 0x5B, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x5D, 0x2E, 0x2E,
    0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x5C, 0x2E, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E
};

void
EBCDIC_to_ASCII(uint8_t *buf, unsigned bytes)
{
    unsigned   i;
    uint8_t *bufptr;

    bufptr = buf;

    for (i = 0; i < bytes; i++, bufptr++) {
        *bufptr = EBCDIC_translate_ASCII[*bufptr];
    }
}

uint8_t
EBCDIC_to_ASCII1(uint8_t c)
{
    return EBCDIC_translate_ASCII[c];
}

/*
 * This routine is based on a routine created by Dan Lasley
 * <DLASLEY@PROMUS.com>.
 *
 * It was modified for Wireshark by Gilbert Ramirez and others.
 */

#define MAX_OFFSET_LEN   8       /* max length of hex offset of bytes */
#define BYTES_PER_LINE  16      /* max byte values printed on a line */
#define HEX_DUMP_LEN    (BYTES_PER_LINE*3)
                                /* max number of characters hex dump takes -
                                   2 digits plus trailing blank */
#define DATA_DUMP_LEN   (HEX_DUMP_LEN + 2 + 2 + BYTES_PER_LINE)
                                /* number of characters those bytes take;
                                   3 characters per byte of hex dump,
                                   2 blanks separating hex from ASCII,
                                   2 optional ASCII dump delimiters,
                                   1 character per byte of ASCII dump */
#define MAX_LINE_LEN    (MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
                                /* number of characters per line;
                                   offset, 2 blanks separating offset
                                   from data dump, data dump */

bool
hex_dump_buffer(bool (*print_line)(void *, const char *), void *fp,
                                    const unsigned char *cp, unsigned length,
                                    hex_dump_enc encoding,
                                    unsigned ascii_option)
{
    register unsigned int ad, i, j, k, l;
    unsigned char         c;
    char                  line[MAX_LINE_LEN + 1];
    unsigned int          use_digits;

    static char binhex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /*
     * How many of the leading digits of the offset will we supply?
     * We always supply at least 4 digits, but if the maximum offset
     * won't fit in 4 digits, we use as many digits as will be needed.
     */
    if (((length - 1) & 0xF0000000) != 0)
        use_digits = 8; /* need all 8 digits */
    else if (((length - 1) & 0x0F000000) != 0)
        use_digits = 7; /* need 7 digits */
    else if (((length - 1) & 0x00F00000) != 0)
        use_digits = 6; /* need 6 digits */
    else if (((length - 1) & 0x000F0000) != 0)
        use_digits = 5; /* need 5 digits */
    else
        use_digits = 4; /* we'll supply 4 digits */

    ad = 0;
    i = 0;
    j = 0;
    k = 0;
    while (i < length) {
        if ((i & 15) == 0) {
            /*
             * Start of a new line.
             */
            j = 0;
            l = use_digits;
            do {
                l--;
                c = (ad >> (l*4)) & 0xF;
                line[j++] = binhex[c];
            } while (l != 0);
            line[j++] = ' ';
            line[j++] = ' ';
            memset(line+j, ' ', DATA_DUMP_LEN);

            /*
             * Offset in line of ASCII dump.
             */
            k = j + HEX_DUMP_LEN + 2;
            if (ascii_option == HEXDUMP_ASCII_DELIMIT)
                line[k++] = '|';
        }
        c = *cp++;
        line[j++] = binhex[c>>4];
        line[j++] = binhex[c&0xf];
        j++;
        if (ascii_option != HEXDUMP_ASCII_EXCLUDE ) {
            if (encoding == HEXDUMP_ENC_EBCDIC) {
                c = EBCDIC_to_ASCII1(c);
            }
            line[k++] = ((c >= ' ') && (c < 0x7f)) ? c : '.';
        }
        i++;
        if (((i & 15) == 0) || (i == length)) {
            /*
             * We'll be starting a new line, or
             * we're finished printing this buffer;
             * dump out the line we've constructed,
             * and advance the offset.
             */
            if (ascii_option == HEXDUMP_ASCII_DELIMIT)
                line[k++] = '|';
            line[k] = '\0';
            if (!print_line(fp, line))
                return false;
            ad += 16;
        }
    }
    return true;
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
