/* strutil.c
 * String utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "strutil.h"

#include <wsutil/str_util.h>
#include <wsutil/unicode-utils.h>
#include <epan/proto.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#endif


/*
 * Given a pointer into a data buffer, and to the end of the buffer,
 * find the end of the (putative) line at that position in the data
 * buffer.
 * Return a pointer to the EOL character(s) in "*eol".
 */
const unsigned char *
find_line_end(const unsigned char *data, const unsigned char *dataend, const unsigned char **eol)
{
    const unsigned char *lineend;

    lineend = (unsigned char *)memchr(data, '\n', dataend - data);
    if (lineend == NULL) {
        /*
         * No LF - line is probably continued in next TCP segment.
         */
        lineend = dataend;
        *eol = dataend;
    } else {
        /*
         * Is the LF at the beginning of the line?
         */
        if (lineend > data) {
            /*
             * No - is it preceded by a carriage return?
             * (Perhaps it's supposed to be, but that's not guaranteed....)
             */
            if (*(lineend - 1) == '\r') {
                /*
                 * Yes.  The EOL starts with the CR.
                 */
                *eol = lineend - 1;
            } else {
                /*
                 * No.  The EOL starts with the LF.
                 */
                *eol = lineend;

                /*
                 * I seem to remember that we once saw lines ending with LF-CR
                 * in an HTTP request or response, so check if it's *followed*
                 * by a carriage return.
                 */
                if (lineend < (dataend - 1) && *(lineend + 1) == '\r') {
                    /*
                     * It's <non-LF><LF><CR>; say it ends with the CR.
                     */
                    lineend++;
                }
            }
        } else {
            /*
             * Yes - the EOL starts with the LF.
             */
            *eol = lineend;
        }

        /*
         * Point to the character after the last character.
         */
        lineend++;
    }
    return lineend;
}

/*
 * Get the length of the next token in a line, and the beginning of the
 * next token after that (if any).
 * Return 0 if there is no next token.
 */
int
get_token_len(const unsigned char *linep, const unsigned char *lineend,
        const unsigned char **next_token)
{
    const unsigned char *tokenp;
    int token_len;

    tokenp = linep;

    /*
     * Search for a blank, a CR or an LF, or the end of the buffer.
     */
    while (linep < lineend && *linep != ' ' && *linep != '\r' && *linep != '\n')
        linep++;
    token_len = (int) (linep - tokenp);

    /*
     * Skip trailing blanks.
     */
    while (linep < lineend && *linep == ' ')
        linep++;

    *next_token = linep;

    return token_len;
}

static bool
is_byte_sep(uint8_t c)
{
    return (c == '-' || c == ':' || c == '.');
}

/* Turn a string of hex digits with optional separators (defined by
 * is_byte_sep() into a byte array.
 *
 * XXX - This function is perhaps too generous in what it accepts.
 * It allows the separator to change from one character to another,
 * or to and from no separator if force_separators is false.
 */
bool
hex_str_to_bytes(const char *hex_str, GByteArray *bytes, bool force_separators)
{
    uint8_t       val;
    const char     *p, *q, *r, *s, *punct;
    char        four_digits_first_half[3];
    char        four_digits_second_half[3];
    char        two_digits[3];
    char        one_digit[2];

    if (! hex_str || ! bytes) {
        return false;
    }
    g_byte_array_set_size(bytes, 0);
    p = hex_str;
    while (*p) {
        q = p+1;
        r = p+2;
        s = p+3;

        if (*q && *r
                && g_ascii_isxdigit(*p) && g_ascii_isxdigit(*q) &&
                g_ascii_isxdigit(*r)) {

            /*
             * Three hex bytes in a row, followed by a non hex byte
             * (possibly the end of the string). We don't accept an
             * odd number of hex digits except for single digits
             * by themselves or after a separator.
             */
            if (!g_ascii_isxdigit(*s)) {
                return false;
            }
            four_digits_first_half[0] = *p;
            four_digits_first_half[1] = *q;
            four_digits_first_half[2] = '\0';
            four_digits_second_half[0] = *r;
            four_digits_second_half[1] = *s;
            four_digits_second_half[2] = '\0';

            /*
             * Four or more hex digits in a row.
             */
            val = (uint8_t) strtoul(four_digits_first_half, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
            val = (uint8_t) strtoul(four_digits_second_half, NULL, 16);
            g_byte_array_append(bytes, &val, 1);

            punct = s + 1;
            if (*punct) {
                /*
                 * Make sure the character after
                 * the fourth hex digit is a byte
                 * separator, i.e. that we don't have
                 * more than four hex digits, or a
                 * bogus character.
                 */
                if (is_byte_sep(*punct)) {
                    p = punct + 1;
                    continue;
                }
                else if (force_separators) {
                    return false;
                }
            }
            p = punct;
            continue;
        }
        else if (*q && g_ascii_isxdigit(*p) && g_ascii_isxdigit(*q)) {
            two_digits[0] = *p;
            two_digits[1] = *q;
            two_digits[2] = '\0';

            /*
             * Two hex digits in a row.
             */
            val = (uint8_t) strtoul(two_digits, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
            punct = q + 1;
            if (*punct) {
                /*
                 * Make sure the character after
                 * the second hex digit is a byte
                 * separator, i.e. that we don't have
                 * more than two hex digits, or a
                 * bogus character.
                 */
                if (is_byte_sep(*punct)) {
                    p = punct + 1;
                    continue;
                }
                else if (force_separators) {
                    return false;
                }
            }
            p = punct;
            continue;
        }
        else if (*q && g_ascii_isxdigit(*p) && is_byte_sep(*q)) {
            one_digit[0] = *p;
            one_digit[1] = '\0';

            /*
             * Only one hex digit (not at the end of the string)
             */
            val = (uint8_t) strtoul(one_digit, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
            p = q + 1;
            continue;
        }
        else if (!*q && g_ascii_isxdigit(*p)) {
            one_digit[0] = *p;
            one_digit[1] = '\0';

            /*
             * Only one hex digit (at the end of the string)
             */
            val = (uint8_t) strtoul(one_digit, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
            p = q;
            continue;
        }
        else {
            return false;
        }
    }
    return true;
}

static inline char
get_valid_byte_sep(char c, const unsigned encoding)
{
    char retval = -1; /* -1 means failure */

    switch (c) {
        case ':':
            if (encoding & ENC_SEP_COLON)
                retval = c;
            break;
        case '-':
            if (encoding & ENC_SEP_DASH)
                retval = c;
            break;
        case '.':
            if (encoding & ENC_SEP_DOT)
                retval = c;
            break;
        case ' ':
            if (encoding & ENC_SEP_SPACE)
                retval = c;
            break;
        case '\0':
            /* we were given the end of the string, so it's fine */
            retval = 0;
            break;
        default:
            if (g_ascii_isxdigit(c) && (encoding & ENC_SEP_NONE))
                retval = 0;
            /* anything else means we've got a failure */
            break;
    }

    return retval;
}

/* Turn a string of hex digits with optional separators (defined by is_byte_sep())
 * into a byte array. Unlike hex_str_to_bytes(), this will read as many hex-char
 * pairs as possible and not error if it hits a non-hex-char; instead it just ends
 * there. (i.e., like strtol()/atoi()/etc.) Unless fail_if_partial is true.
 *
 * The **endptr, if not NULL, is set to the char after the last hex character.
 */
bool
hex_str_to_bytes_encoding(const char *hex_str, GByteArray *bytes, const char **endptr,
                          const unsigned encoding, const bool fail_if_partial)
{
    int8_t c, d;
    uint8_t val;
    const char *end = hex_str;
    bool retval = false;
    char sep = -1;

    /* a map from ASCII hex chars to their value */
    static const int8_t str_to_nibble[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    /* we must see two hex chars at the beginning, or fail */
    if (bytes && *end && g_ascii_isxdigit(*end) && g_ascii_isxdigit(*(end+1))) {
        retval = true;

        /* set the separator character we'll allow; if this returns a -1, it means something's
         * invalid after the hex, but we'll let the while-loop grab the first hex-pair anyway
         */
        sep = get_valid_byte_sep(*(end+2), encoding);

        while (*end) {
            c = str_to_nibble[(unsigned char)*end];
            if (c < 0) {
                if (fail_if_partial) retval = false;
                break;
            }

            d = str_to_nibble[(unsigned char)*(end+1)];
            if (d < 0) {
                if (fail_if_partial) retval = false;
                break;
            }
            val = ((uint8_t)c * 16) + d;
            g_byte_array_append(bytes, &val, 1);
            end += 2;

            /* check for separator and peek at next char to make sure we should keep going */
            if (sep > 0 && *end == sep && str_to_nibble[(unsigned char)*(end+1)] > -1) {
                /* yes, it's the right sep and followed by more hex, so skip the sep */
                ++end;
            } else if (sep != 0 && *end) {
                /* we either need a separator, but we don't see one; or the get_valid_byte_sep()
                   earlier didn't find a valid one to begin with */
                if (fail_if_partial) retval = false;
                break;
            }
            /* otherwise, either no separator allowed, or *end is null, or *end is an invalid
             * sep, or *end is a valid sep but after it is not a hex char - in all those
             * cases, just loop back up and let it fail later naturally.
             */
        }
    }

    if (!retval) {
        if (bytes) g_byte_array_set_size(bytes, 0);
        end = hex_str;
    }

    if (endptr) *endptr = end;

    return retval;
}

/*
 * Turn an RFC 3986 percent-encoded array of characters, not
 * necessarily null-terminated, into a byte array.
 * XXX - We don't check for reserved characters.
 * XXX - g_uri_unescape_bytes is superior, but limited to
 * glib >= 2.66
 */
#define HEX_DIGIT_BUF_LEN 3
bool
uri_to_bytes(const char *uri_str, GByteArray *bytes, size_t len)
{
    uint8_t       val;
    const char   *p;
    const char   *uri_end = uri_str + len;
    char          hex_digit[HEX_DIGIT_BUF_LEN];

    g_byte_array_set_size(bytes, 0);
    if (! uri_str) {
        return false;
    }

    p = uri_str;

    while (p < uri_end) {
        if (!g_ascii_isprint(*p))
            return false;
        if (*p == '%') {
            p++;
            if (*p == '\0') return false;
            hex_digit[0] = *p;
            p++;
            if (*p == '\0') return false;
            hex_digit[1] = *p;
            hex_digit[2] = '\0';
            if (! g_ascii_isxdigit(hex_digit[0]) || ! g_ascii_isxdigit(hex_digit[1]))
                return false;
            val = (uint8_t) strtoul(hex_digit, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
        } else {
            g_byte_array_append(bytes, (const uint8_t *) p, 1);
        }
        p++;

    }
    return true;
}

/*
 * Turn an RFC 3986 percent-encoded string into a byte array.
 * XXX - We don't check for reserved characters.
 * XXX - Just use g_uri_unescape_string instead?
 */
bool
uri_str_to_bytes(const char *uri_str, GByteArray *bytes)
{
    return uri_to_bytes(uri_str, bytes, strlen(uri_str));
}

/**
 * Create a copy of a GByteArray
 *
 * @param ba The byte array to be copied.
 * @return If ba exists, a freshly allocated copy.  NULL otherwise.
 *
 */
GByteArray *
byte_array_dup(const GByteArray *ba)
{
    GByteArray *new_ba;

    if (!ba)
        return NULL;

    new_ba = g_byte_array_new();
    g_byte_array_append(new_ba, ba->data, ba->len);
    return new_ba;
}

#define SUBID_BUF_LEN 5
bool
oid_str_to_bytes(const char *oid_str, GByteArray *bytes)
{
    return rel_oid_str_to_bytes(oid_str, bytes, true);
}
bool
rel_oid_str_to_bytes(const char *oid_str, GByteArray *bytes, bool is_absolute)
{
    uint32_t subid0, subid, sicnt, i;
    const char *p, *dot;
    uint8_t buf[SUBID_BUF_LEN];

    g_byte_array_set_size(bytes, 0);

    /* check syntax */
    p = oid_str;
    dot = NULL;
    while (*p) {
        if (!g_ascii_isdigit(*p) && (*p != '.')) return false;
        if (*p == '.') {
            if (p == oid_str && is_absolute) return false;
            if (!*(p+1)) return false;
            if ((p-1) == dot) return false;
            dot = p;
        }
        p++;
    }
    if (!dot) return false;

    p = oid_str;
    sicnt = is_absolute ? 0 : 2;
    if (!is_absolute) p++;
    subid0 = 0;    /* squelch GCC complaints */
    while (*p) {
        subid = 0;
        while (g_ascii_isdigit(*p)) {
            subid *= 10;
            subid += *p - '0';
            p++;
        }
        if (sicnt == 0) {
            subid0 = subid;
            if (subid0 > 2) return false;
        } else if (sicnt == 1) {
            if ((subid0 < 2) && (subid > 39)) return false;
            subid += 40 * subid0;
        }
        if (sicnt) {
            i = SUBID_BUF_LEN;
            do {
                i--;
                buf[i] = 0x80 | (subid % 0x80);
                subid >>= 7;
            } while (subid && i);
            buf[SUBID_BUF_LEN-1] &= 0x7F;
            g_byte_array_append(bytes, buf + i, SUBID_BUF_LEN - i);
        }
        sicnt++;
        if (*p) p++;
    }

    return true;
}

/**
 * Compare the contents of two GByteArrays
 *
 * @param ba1 A byte array
 * @param ba2 A byte array
 * @return If both arrays are non-NULL and their lengths are equal and
 *         their contents are equal, returns true.  Otherwise, returns
 *         false.
 *
 * XXX - Should this be in strutil.c?
 */
bool
byte_array_equal(GByteArray *ba1, GByteArray *ba2)
{
    if (!ba1 || !ba2)
        return false;

    if (ba1->len != ba2->len)
        return false;

    if (memcmp(ba1->data, ba2->data, ba1->len) != 0)
        return false;

    return true;
}


/* Return a XML escaped representation of the unescaped string.
 * The returned string must be freed when no longer in use. */
char *
xml_escape(const char *unescaped)
{
    GString *buffer = g_string_sized_new(128);
    const char *p;
    char c;

    p = unescaped;
    while ( (c = *p++) ) {
        switch (c) {
            case '<':
                g_string_append(buffer, "&lt;");
                break;
            case '>':
                g_string_append(buffer, "&gt;");
                break;
            case '&':
                g_string_append(buffer, "&amp;");
                break;
            case '\'':
                g_string_append(buffer, "&#x27;");
                break;
            case '"':
                g_string_append(buffer, "&quot;");
                break;
            case '\t':
            case '\n':
            case '\r':
                g_string_append_c(buffer, c);
                break;
            default:
                /* XML 1.0 doesn't allow ASCII control characters, except
                 * for the three whitespace ones above (which do *not*
                 * include '\v' and '\f', so not the same group as isspace),
                 * even as character references.
                 * There's no official way to escape them, so we'll do this. */
                if (g_ascii_iscntrl(c)) {
                    g_string_append_printf(buffer, "\\x%x", c);
                } else {
                    g_string_append_c(buffer, c);
                }
                break;
        }
    }
    /* Return the string value contained within the GString
     * after getting rid of the GString structure.
     * This is the way to do this, see the GLib reference. */
    return g_string_free(buffer, FALSE);
}

/*
 * Scan the search string to make sure it's valid hex.  Return the
 * number of bytes in nbytes.
 */
uint8_t *
convert_string_to_hex(const char *string, size_t *nbytes)
{
    size_t n_bytes;
    const char *p;
    char c;
    uint8_t *bytes, *q, byte_val;

    n_bytes = 0;
    p = &string[0];
    for (;;) {
        c = *p++;
        if (c == '\0')
            break;
        if (g_ascii_isspace(c))
            continue;    /* allow white space */
        if (c==':' || c=='.' || c=='-')
            continue; /* skip any ':', '.', or '-' between bytes */
        if (!g_ascii_isxdigit(c)) {
            /* Not a valid hex digit - fail */
            return NULL;
        }

        /*
         * We can only match bytes, not nibbles; we must have a valid
         * hex digit immediately after that hex digit.
         */
        c = *p++;
        if (!g_ascii_isxdigit(c))
            return NULL;

        /* 2 hex digits = 1 byte */
        n_bytes++;
    }

    /*
     * Were we given any hex digits?
     */
    if (n_bytes == 0) {
        /* No. */
        return NULL;
    }

    /*
     * OK, it's valid, and it generates "n_bytes" bytes; generate the
     * raw byte array.
     */
    bytes = (uint8_t *)g_malloc(n_bytes);
    p = &string[0];
    q = &bytes[0];
    for (;;) {
        c = *p++;
        if (c == '\0')
            break;
        if (g_ascii_isspace(c))
            continue;    /* allow white space */
        if (c==':' || c=='.' || c=='-')
            continue; /* skip any ':', '.', or '-' between bytes */
        /* From the loop above, we know this is a hex digit */
        byte_val = ws_xton(c);
        byte_val <<= 4;

        /* We also know this is a hex digit */
        c = *p++;
        byte_val |= ws_xton(c);

        *q++ = byte_val;
    }
    *nbytes = n_bytes;
    return bytes;
}

/*
 * Copy if it's a case-sensitive search; uppercase it if it's
 * a case-insensitive search.
 */
char *
convert_string_case(const char *string, bool case_insensitive)
{

    if (case_insensitive) {
        return g_utf8_strup(string, -1);
    } else {
        return g_strdup(string);
    }
}

#define GN_CHAR_ALPHABET_SIZE 128

static gunichar IA5_default_alphabet[GN_CHAR_ALPHABET_SIZE] = {

    /*ITU-T recommendation T.50 specifies International Reference Alphabet 5 (IA5) */

    '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?',
    '?', '?', '?', '?', '?', '?', '?', '?',
    ' ', '!', '\"','#', '$', '%', '&', '\'',
    '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  '[',  '\\',  ']',  '^',  '_',
    '`', 'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  '{',  '|',  '}',  '~',  '?'
};

static gunichar
char_def_ia5_alphabet_decode(unsigned char value)
{
    if (value < GN_CHAR_ALPHABET_SIZE) {
        return IA5_default_alphabet[value];
    }
    else {
        return '?';
    }
}

void
IA5_7BIT_decode(unsigned char * dest, const unsigned char* src, int len)
{
    int i, j;
    gunichar buf;

    for (i = 0, j = 0; j < len;  j++) {
        buf = char_def_ia5_alphabet_decode(src[j]);
        i += g_unichar_to_utf8(buf,&(dest[i]));
    }
    dest[i]=0;
}

/* chars allowed: lower case letters, digits, '-', "_", and ".". */
static
const uint8_t module_valid_chars_lower_case[128] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00-0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10-0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, /* 0x20-0x2F '-', '.'      */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30-0x3F '0'-'9'       */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40-0x4F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, /* 0x50-0x5F '_' */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60-0x6F 'a'-'o'       */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 0x70-0x7F 'p'-'z'       */
};

/* chars allowed: alphanumerics, '-', "_", and ".". */
static
const uint8_t module_valid_chars[128] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00-0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10-0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, /* 0x20-0x2F '-', '.'      */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30-0x3F '0'-'9'       */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x40-0x4F 'A'-'O'       */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, /* 0x50-0x5F 'P'-'Z', '_' */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60-0x6F 'a'-'o'       */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 0x70-0x7F 'p'-'z'       */
};

unsigned char
module_check_valid_name(const char *name, bool lower_only)
{
    const char *p = name;
    unsigned char c = '.', lastc;
    const uint8_t *chars;

    /* First character cannot be '-'. */
    if (name[0] == '-')
        return '-';

    if (lower_only)
        chars = module_valid_chars_lower_case;
    else
        chars = module_valid_chars;

    do {
        lastc = c;
        c = *(p++);
        /* Leading '.' or substring ".." are disallowed. */
        if (c == '.' && lastc == '.') {
            break;
        }
    } while (c < 128 && chars[c]);

    /* Trailing '.' is disallowed. */
    if (lastc == '.') {
        return '.';
    }
    return c;
}

static const char _hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/*
 * Copy byte by byte without UTF-8 truncation (assume valid UTF-8 input).
 * Return byte size written, or that would have been
 * written with enough space.
 */
size_t
ws_label_strcpy(char *label_str, size_t buf_size, size_t pos,
                const uint8_t *str, int flags)
{
    if (pos >= buf_size)
        return pos;

    uint8_t r = 0;
    ssize_t chlen;
    ssize_t idx, src_len;
    ssize_t free_len;

    label_str[pos] = '\0';

    ws_return_val_if(str == NULL, pos);
    idx = 0;
    src_len = strlen(str);
    free_len = buf_size - pos - 1;

    while (idx < src_len) {
        chlen = ws_utf8_char_len(str[idx]);
        if (chlen <= 0) {
            /* We were passed invalid UTF-8. This is an error. Complain and do... something. */
            ws_log_utf8(str, -1, NULL);
            /*
             * XXX If we are going to return here instead of trying to recover maybe the log level should
             * be higher than DEBUG.
             */
            return pos;
        }

        /* ASCII */
        if (chlen == 1) {
            if (flags & FORMAT_LABEL_REPLACE_SPACE && g_ascii_isspace(str[idx])) {
                if (free_len >= 1) {
                    label_str[pos] = ' ';
                    label_str[pos+1] = '\0';
                }
                pos++;
                idx++;
                free_len--;
                continue;
            }

            r = 0;
            switch (str[idx]) {
                case '\a': r = 'a'; break;
                case '\b': r = 'b'; break;
                case '\f': r = 'f'; break;
                case '\n': r = 'n'; break;
                case '\r': r = 'r'; break;
                case '\t': r = 't'; break;
                case '\v': r = 'v'; break;
            }
            if (r != 0) {
                if (free_len >= 2) {
                    label_str[pos] = '\\';
                    label_str[pos+1] = r;
                    label_str[pos+2] = '\0';
                }
                pos += 2;
                idx += 1;
                free_len -= 2;
                continue;
            }

            if (g_ascii_isprint(str[idx])) {
                if (free_len >= 1) {
                    label_str[pos] = str[idx];
                    label_str[pos+1] = '\0';
                }
                pos++;
                idx++;
                free_len--;
                continue;
            }

            if (free_len >= 4) {
                label_str[pos+0] = '\\';
                label_str[pos+1] = 'x';

                uint8_t ch = str[idx];
                label_str[pos+2] = _hex[ch >> 4];
                label_str[pos+3] = _hex[ch & 0x0F];
                label_str[pos+4] = '\0';
            }
            pos += 4;
            idx += chlen;
            free_len -= 4;
            continue;
        }

        /* UTF-8 multibyte */
        if (chlen == 2 && str[idx] == 0xC2 &&
                                str[idx+1] >= 0x80 && str[idx+1] <= 0x9F) {
            /*
             * Escape the C1 control codes. C0 (covered above) and C1 are
             * inband signalling and transparent to Unicode.
             * Anything else probably has text semantics should not be removed.
             */
            /*
             * Special case: The second UTF-8 byte is the same as the Unicode
             * code point for range U+0080 - U+009F.
             */
            if (free_len >= 6) {
                label_str[pos+0] = '\\';
                label_str[pos+1] = 'u';
                label_str[pos+2] = '0';
                label_str[pos+3] = '0';

                uint8_t ch = str[idx+1];
                label_str[pos+4] = _hex[ch >> 4];
                label_str[pos+5] = _hex[ch & 0x0F];
                label_str[pos+6] = '\0';
            }
            pos += 6;
            idx += chlen;
            free_len -= 6;
            continue;
        }

        /* Just copy */
        if (free_len >= chlen) {
            for (ssize_t j = 0; j < chlen; j++) {
                label_str[pos+j] = str[idx+j];
            }
            label_str[pos+chlen] = '\0';
        }
        pos += chlen;
        idx += chlen;
        free_len -= chlen;
    }

    return pos;
}

size_t
ws_label_strcat(char *label_str, size_t bufsize, const uint8_t *str, int flags)
{
    return ws_label_strcpy(label_str, bufsize, strlen(label_str), str, flags);
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
