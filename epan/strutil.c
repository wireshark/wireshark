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
#include <epan/proto.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#endif

static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

/*
 * Given a pointer into a data buffer, and to the end of the buffer,
 * find the end of the (putative) line at that position in the data
 * buffer.
 * Return a pointer to the EOL character(s) in "*eol".
 */
const guchar *
find_line_end(const guchar *data, const guchar *dataend, const guchar **eol)
{
    const guchar *lineend;

    lineend = (guchar *)memchr(data, '\n', dataend - data);
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
get_token_len(const guchar *linep, const guchar *lineend,
        const guchar **next_token)
{
    const guchar *tokenp;
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
gchar *
format_text(wmem_allocator_t *allocator,
                        const guchar *string, size_t len)
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
gchar *
format_text_string(wmem_allocator_t* allocator, const guchar *string)
{
    return format_text_internal(allocator, string, strlen(string), FALSE);
}

/*
 * Given a string, generate a string from it that shows non-printable
 * characters as C-style escapes except a whitespace character
 * (space, tab, carriage return, new line, vertical tab, or formfeed)
 * which will be replaced by a space, and return a pointer to it.
 */
gchar *
format_text_wsp(wmem_allocator_t* allocator, const guchar *string, size_t len)
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

static gboolean
is_byte_sep(guint8 c)
{
    return (c == '-' || c == ':' || c == '.');
}

/* Turn a string of hex digits with optional separators (defined by
 * is_byte_sep() into a byte array.
 */
gboolean
hex_str_to_bytes(const char *hex_str, GByteArray *bytes, gboolean force_separators)
{
    guint8        val;
    const gchar    *p, *q, *r, *s, *punct;
    char        four_digits_first_half[3];
    char        four_digits_second_half[3];
    char        two_digits[3];
    char        one_digit[2];

    if (! hex_str || ! bytes) {
        return FALSE;
    }
    g_byte_array_set_size(bytes, 0);
    p = hex_str;
    while (*p) {
        q = p+1;
        r = p+2;
        s = p+3;

        if (*q && *r && *s
                && g_ascii_isxdigit(*p) && g_ascii_isxdigit(*q) &&
                g_ascii_isxdigit(*r) && g_ascii_isxdigit(*s)) {
            four_digits_first_half[0] = *p;
            four_digits_first_half[1] = *q;
            four_digits_first_half[2] = '\0';
            four_digits_second_half[0] = *r;
            four_digits_second_half[1] = *s;
            four_digits_second_half[2] = '\0';

            /*
             * Four or more hex digits in a row.
             */
            val = (guint8) strtoul(four_digits_first_half, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
            val = (guint8) strtoul(four_digits_second_half, NULL, 16);
            g_byte_array_append(bytes, &val, 1);

            punct = s + 1;
            if (*punct) {
                /*
                 * Make sure the character after
                 * the forth hex digit is a byte
                 * separator, i.e. that we don't have
                 * more than four hex digits, or a
                 * bogus character.
                 */
                if (is_byte_sep(*punct)) {
                    p = punct + 1;
                    continue;
                }
                else if (force_separators) {
                    return FALSE;
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
            val = (guint8) strtoul(two_digits, NULL, 16);
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
                    return FALSE;
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
            val = (guint8) strtoul(one_digit, NULL, 16);
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
            val = (guint8) strtoul(one_digit, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
            p = q;
            continue;
        }
        else {
            return FALSE;
        }
    }
    return TRUE;
}

static inline gchar
get_valid_byte_sep(gchar c, const guint encoding)
{
    gchar retval = -1; /* -1 means failure */

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
 * there. (i.e., like strtol()/atoi()/etc.) Unless fail_if_partial is TRUE.
 *
 * The **endptr, if not NULL, is set to the char after the last hex character.
 */
gboolean
hex_str_to_bytes_encoding(const gchar *hex_str, GByteArray *bytes, const gchar **endptr,
                          const guint encoding, const gboolean fail_if_partial)
{
    gint8 c, d;
    guint8 val;
    const gchar *end = hex_str;
    gboolean retval = FALSE;
    gchar sep = -1;

    /* a map from ASCII hex chars to their value */
    static const gint8 str_to_nibble[256] = {
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
        retval = TRUE;

        /* set the separator character we'll allow; if this returns a -1, it means something's
         * invalid after the hex, but we'll let the while-loop grab the first hex-pair anyway
         */
        sep = get_valid_byte_sep(*(end+2), encoding);

        while (*end) {
            c = str_to_nibble[(guchar)*end];
            if (c < 0) {
                if (fail_if_partial) retval = FALSE;
                break;
            }
            ++end;

            d = str_to_nibble[(guchar)*end];
            if (d < 0) {
                if (fail_if_partial) retval = FALSE;
                break;
            }
            val = ((guint8)c * 16) + d;
            g_byte_array_append(bytes, &val, 1);
            ++end;

            /* check for separator and peek at next char to make sure we should keep going */
            if (sep > 0 && *end == sep && str_to_nibble[(guchar)*(end+1)] > -1) {
                /* yes, it's the right sep and followed by more hex, so skip the sep */
                ++end;
            } else if (sep != 0 && *end) {
                /* we either need a separator, but we don't see one; or the get_valid_byte_sep()
                   earlier didn't find a valid one to begin with */
                if (fail_if_partial) retval = FALSE;
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
gboolean
uri_to_bytes(const char *uri_str, GByteArray *bytes, size_t len)
{
    guint8        val;
    const gchar  *p;
    const gchar  *uri_end = uri_str + len;
    gchar         hex_digit[HEX_DIGIT_BUF_LEN];

    g_byte_array_set_size(bytes, 0);
    if (! uri_str) {
        return FALSE;
    }

    p = uri_str;

    while (p < uri_end) {
        if (!g_ascii_isprint(*p))
            return FALSE;
        if (*p == '%') {
            p++;
            if (*p == '\0') return FALSE;
            hex_digit[0] = *p;
            p++;
            if (*p == '\0') return FALSE;
            hex_digit[1] = *p;
            hex_digit[2] = '\0';
            if (! g_ascii_isxdigit(hex_digit[0]) || ! g_ascii_isxdigit(hex_digit[1]))
                return FALSE;
            val = (guint8) strtoul(hex_digit, NULL, 16);
            g_byte_array_append(bytes, &val, 1);
        } else {
            g_byte_array_append(bytes, (const guint8 *) p, 1);
        }
        p++;

    }
    return TRUE;
}

/*
 * Turn an RFC 3986 percent-encoded string into a byte array.
 * XXX - We don't check for reserved characters.
 * XXX - Just use g_uri_unescape_string instead?
 */
gboolean
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
gboolean
oid_str_to_bytes(const char *oid_str, GByteArray *bytes)
{
    return rel_oid_str_to_bytes(oid_str, bytes, TRUE);
}
gboolean
rel_oid_str_to_bytes(const char *oid_str, GByteArray *bytes, gboolean is_absolute)
{
    guint32 subid0, subid, sicnt, i;
    const char *p, *dot;
    guint8 buf[SUBID_BUF_LEN];

    g_byte_array_set_size(bytes, 0);

    /* check syntax */
    p = oid_str;
    dot = NULL;
    while (*p) {
        if (!g_ascii_isdigit(*p) && (*p != '.')) return FALSE;
        if (*p == '.') {
            if (p == oid_str && is_absolute) return FALSE;
            if (!*(p+1)) return FALSE;
            if ((p-1) == dot) return FALSE;
            dot = p;
        }
        p++;
    }
    if (!dot) return FALSE;

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
            if (subid0 > 2) return FALSE;
        } else if (sicnt == 1) {
            if ((subid0 < 2) && (subid > 39)) return FALSE;
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

    return TRUE;
}

/**
 * Compare the contents of two GByteArrays
 *
 * @param ba1 A byte array
 * @param ba2 A byte array
 * @return If both arrays are non-NULL and their lengths are equal and
 *         their contents are equal, returns TRUE.  Otherwise, returns
 *         FALSE.
 *
 * XXX - Should this be in strutil.c?
 */
gboolean
byte_array_equal(GByteArray *ba1, GByteArray *ba2)
{
    if (!ba1 || !ba2)
        return FALSE;

    if (ba1->len != ba2->len)
        return FALSE;

    if (memcmp(ba1->data, ba2->data, ba1->len) != 0)
        return FALSE;

    return TRUE;
}


/* Return a XML escaped representation of the unescaped string.
 * The returned string must be freed when no longer in use. */
gchar *
xml_escape(const gchar *unescaped)
{
    GString *buffer = g_string_sized_new(128);
    const gchar *p;
    gchar c;

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
            default:
                g_string_append_c(buffer, c);
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
guint8 *
convert_string_to_hex(const char *string, size_t *nbytes)
{
    size_t n_bytes;
    const char *p;
    gchar c;
    guint8 *bytes, *q, byte_val;

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
    bytes = (guint8 *)g_malloc(n_bytes);
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
convert_string_case(const char *string, gboolean case_insensitive)
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
const guint8 module_valid_chars_lower_case[128] = {
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
const guint8 module_valid_chars[128] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00-0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10-0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, /* 0x20-0x2F '-', '.'      */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30-0x3F '0'-'9'       */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x40-0x4F 'A'-'O'       */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, /* 0x50-0x5F 'P'-'Z', '_' */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60-0x6F 'a'-'o'       */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 0x70-0x7F 'p'-'z'       */
};

guchar
module_check_valid_name(const char *name, gboolean lower_only)
{
    const char *p = name;
    guchar c = '.', lastc;
    const guint8 *chars;

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
