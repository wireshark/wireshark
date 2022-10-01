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


static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

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
isprint_utf8_string(const gchar *str, const guint length)
{
    const gchar *strend = str + length;

    if (!g_utf8_validate(str, length, NULL)) {
        return FALSE;
    }

    while (str < strend) {
        /* This returns false for G_UNICODE_CONTROL | G_UNICODE_FORMAT |
         * G_UNICODE_UNASSIGNED | G_UNICODE_SURROGATE
         * XXX: Could it be ok to have certain format characters, e.g.
         * U+00AD SOFT HYPHEN? If so, format_text() should be changed too.
         */
        if (!g_unichar_isprint(g_utf8_get_char(str))) {
            return FALSE;
        }
        str = g_utf8_next_char(str);
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
     * Backslashes and double-quotes must
     * be escaped. Whitespace is also escaped.
     */
    switch (c) {
        case '\a': r = 'a'; break;
        case '\b': r = 'b'; break;
        case '\f': r = 'f'; break;
        case '\n': r = 'n'; break;
        case '\r': r = 'r'; break;
        case '\t': r = 't'; break;
        case '\v': r = 'v'; break;
        case '"':  r = '"'; break;
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
                    bool (*escape_func)(char c, char *p), bool add_quotes)
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

    buf = wmem_strbuf_sized_new(alloc, alloc_size, 0);

    if (add_quotes)
        wmem_strbuf_append_c(buf, '"');

    for (i = 0; i < len; i++) {
        c = string[i];
        if ((escape_func(c, &r))) {
            wmem_strbuf_append_c(buf, '\\');
            wmem_strbuf_append_c(buf, r);
        }
        else {
            /* Other UTF-8 bytes are passed through. */
            wmem_strbuf_append_c(buf, c);
        }
    }

    if (add_quotes)
        wmem_strbuf_append_c(buf, '"');

    return wmem_strbuf_finalize(buf);
}

char *
ws_escape_string_len(wmem_allocator_t *alloc, const char *string, ssize_t len, bool add_quotes)
{
    return escape_string_len(alloc, string, len, escape_char, add_quotes);
}

char *
ws_escape_string(wmem_allocator_t *alloc, const char *string, bool add_quotes)
{
    return escape_string_len(alloc, string, -1, escape_char, add_quotes);
}

char *ws_escape_null(wmem_allocator_t *alloc, const char *string, size_t len, bool add_quotes)
{
    return escape_string_len(alloc, string, len, escape_null, add_quotes);
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

    wmem_strbuf_t *buf = wmem_strbuf_sized_new(allocator, offset + len, 0);

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
    gchar *fmtbuf = (gchar*)wmem_alloc(allocator, INITIAL_FMTBUF_SIZE); \
    guint fmtbuf_len = INITIAL_FMTBUF_SIZE; \
    guint column = 0

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
        fmtbuf = (gchar *)wmem_realloc(allocator, fmtbuf, fmtbuf_len); \
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

/* REPLACEMENT CHARACTER */
#define UNREPL 0xFFFD

#define UNPOOP 0x1F4A9

static gchar *
format_text_internal(wmem_allocator_t *allocator,
                        const guchar *string, size_t len,
                        gboolean replace_space)
{
    FMTBUF_VARS;
    const guchar *stringend = string + len;
    guchar c;

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
            guchar mask;
            gunichar uc;
            guchar first;

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
                        uc = UNREPL;
                        break;
                    }
                    c = *string;
                    if ((c & 0xc0) != 0x80) {
                        /*
                         * Not valid UTF-8 continuation character; put in
                         * a replacement character, and then re-process
                         * this octet as the beginning of a new character.
                         */
                        uc = UNREPL;
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
                    uc = UNREPL;
            } else {
                /* 0xfe or 0xff; put it a REPLACEMENT CHARACTER */
                uc = UNREPL;
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
    return format_text_internal(allocator, string, len, FALSE);
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
    return format_text_internal(allocator, string, strlen(string), FALSE);
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
    return format_text_internal(allocator, string, len, TRUE);
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

    buf = wmem_strbuf_sized_new(allocator, len + 1, 0);
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
