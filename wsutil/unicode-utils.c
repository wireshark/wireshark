/* unicode-utils.c
 * Unicode utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "unicode-utils.h"

const int ws_utf8_seqlen[256] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x00...0x0f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x10...0x1f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x20...0x2f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x30...0x3f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x40...0x4f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x50...0x5f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x60...0x6f */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,  /* 0x70...0x7f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x80...0x8f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x90...0x9f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xa0...0xaf */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xb0...0xbf */
    0,0,2,2,2,2,2,2,2,2,2,2,2,2,2,2,  /* 0xc0...0xcf */
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,  /* 0xd0...0xdf */
    3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,  /* 0xe0...0xef */
    4,4,4,4,4,0,0,0,0,0,0,0,0,0,0,0,  /* 0xf0...0xff */
};

/* Given a pointer and a length, validates a string of bytes as UTF-8.
 * Returns the number of valid bytes, and a pointer immediately past
 * the checked region.
 *
 * Differs from Glib's g_utf8_validate_len in that null bytes are
 * considered valid UTF-8, and that maximal subparts are replaced as
 * a unit. (I.e., given a sequence of 2 or 3 bytes which are a
 * truncated version of a 3 or 4 byte UTF-8 character, but the next
 * byte does not continue the character, the set of 2 or 3 bytes
 * are replaced with one REPLACMENT CHARACTER.)
 */
static inline size_t
utf_8_validate(const uint8_t *start, ssize_t length, const uint8_t **end)
{
    const uint8_t *ptr = start;
    uint8_t ch;
    size_t unichar_len, valid_bytes = 0;

    while (length > 0) {

        ch = *ptr;

        if (ch < 0x80) {
            valid_bytes++;
            ptr++;
            length--;
            continue;
        }

        ch = *ptr;

        if (ch < 0xc2 || ch > 0xf4) {
            ptr++;
            length--;
            *end = ptr;
            return valid_bytes;
        }

        if (ch < 0xe0) { /* 110xxxxx, 2 byte char */
            unichar_len = 2;
        } else if (ch < 0xf0) { /* 1110xxxx, 3 byte char */
            unichar_len = 3;
            ptr++;
            length--;
            if (length < 1) {
                *end = ptr;
                return valid_bytes;
            }
            switch (ch) {
                case 0xe0:
                    if (*ptr < 0xa0 || *ptr > 0xbf) {
                        *end = ptr;
                        return valid_bytes;
                    }
                    break;
                case 0xed:
                    if (*ptr < 0x80 || *ptr > 0x9f) {
                        *end = ptr;
                        return valid_bytes;
                    }
                    break;
                default:
                    if (*ptr < 0x80 || *ptr > 0xbf) {
                        *end = ptr;
                        return valid_bytes;
                    }
            }
        } else { /* 11110xxx, 4 byte char - > 0xf4 excluded above */
            unichar_len = 4;
            ptr++;
            length--;
            if (length < 1) {
                *end = ptr;
                return valid_bytes;
            }
            switch (ch) {
                case 0xf0:
                    if (*ptr < 0x90 || *ptr > 0xbf) {
                        *end = ptr;
                        return valid_bytes;
                    }
                    break;
                case 0xf4:
                    if (*ptr < 0x80 || *ptr > 0x8f) {
                        *end = ptr;
                        return valid_bytes;
                    }
                    break;
                default:
                    if (*ptr < 0x80 || *ptr > 0xbf) {
                        *end = ptr;
                        return valid_bytes;
                    }
            }
            ptr++;
            length--;
            if (length < 1) {
                *end = ptr;
                return valid_bytes;
            }
            if (*ptr < 0x80 || *ptr > 0xbf) {
                *end = ptr;
                return valid_bytes;
            }
        }

        ptr++;
        length--;
        if (length < 1) {
            *end = ptr;
            return valid_bytes;
        }
        if (*ptr < 0x80 || *ptr > 0xbf) {
            *end = ptr;
            return valid_bytes;
        } else {
            ptr++;
            length--;
            valid_bytes += unichar_len;
        }

    }
    *end = ptr;
    return valid_bytes;
}

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UTF-8 string, and return a
 * pointer to a UTF-8 string, allocated using the wmem scope, with all
 * ill-formed sequences replaced with the Unicode REPLACEMENT CHARACTER
 * according to the recommended "best practices" given in the Unicode
 * Standard and specified by W3C/WHATWG.
 *
 * Note that in conformance with the Unicode Standard, this treats three
 * byte sequences corresponding to UTF-16 surrogate halves (paired or unpaired)
 * and two byte overlong encodings of 7-bit ASCII characters as invalid and
 * substitutes REPLACEMENT CHARACTER for them. Explicit support for nonstandard
 * derivative encoding formats (e.g. CESU-8, Java Modified UTF-8, WTF-8) could
 * be added later.
 *
 * Compared with g_utf8_make_valid(), this function does not consider
 * internal NUL bytes as invalid and replace them with replacment characters.
 * It also replaces maximal subparts as a unit; i.e., a sequence of 2 or 3
 * bytes which are a truncated version of a valid 3 or 4 byte character (but
 * the next byte does not continue the character) are replaced with a single
 * REPLACEMENT CHARACTER, whereas the Glib function replaces each byte of the
 * sequence with its own (3 octet) REPLACEMENT CHARACTER.
 *
 * XXX: length should probably be a size_t instead of a int in all
 * these encoding functions
 * XXX: the buffer returned can be of different length than the input,
 * and can have internal NULs as well (so that strlen doesn't give its
 * length). As with the other encoding functions, we should return the
 * length of the output buffer (or a wmem_strbuf_t directly) and an
 * indication of whether there was an invalid character (i.e.
 * REPLACEMENT CHARACTER was used.)
 */
wmem_strbuf_t *
ws_utf8_make_valid_strbuf(wmem_allocator_t *scope, const uint8_t *ptr, ssize_t length)
{
    wmem_strbuf_t *str;

    str = wmem_strbuf_new_sized(scope, length+1);

    /* See the Unicode Standard conformance chapter at
     * https://www.unicode.org/versions/Unicode15.0.0/ch03.pdf especially
     * Table 3-7 "Well-Formed UTF-8 Byte Sequences" and
     * U+FFFD Substitution of Maximal Subparts. */

    while (length > 0) {
        const uint8_t *prev = ptr;
        size_t valid_bytes = utf_8_validate(prev, length, &ptr);

        if (valid_bytes) {
            wmem_strbuf_append_len(str, prev, valid_bytes);
        }
        length -= ptr - prev;
        prev += valid_bytes;
        if (ptr - prev) {
            wmem_strbuf_append_unichar_repl(str);
        }
    }

    return str;
}

uint8_t *
ws_utf8_make_valid(wmem_allocator_t *scope, const uint8_t *ptr, ssize_t length)
{
    wmem_strbuf_t *str = ws_utf8_make_valid_strbuf(scope, ptr, length);
    return wmem_strbuf_finalize(str);
}

#ifdef _WIN32

#include <strsafe.h>

/** @file
 * Unicode utilities (internal interface)
 *
 * We define UNICODE and _UNICODE under Windows.  This means that
 * Windows SDK routines expect UTF-16 strings, in contrast to newer
 * versions of Glib and GTK+ which expect UTF-8.  This module provides
 * convenience routines for converting between UTF-8 and UTF-16.
 */

#define INITIAL_UTFBUF_SIZE 128

/*
 * XXX - Should we use g_utf8_to_utf16() and g_utf16_to_utf8()
 * instead?  The goal of the functions below was to provide simple
 * wrappers for UTF-8 <-> UTF-16 conversion without making the
 * caller worry about freeing up memory afterward.
 */

/* Convert from UTF-8 to UTF-16. */
const wchar_t *
utf_8to16(const char *utf8str)
{
    static wchar_t *utf16buf[3];
    static int utf16buf_len[3];
    static int idx;

    if (utf8str == NULL)
        return NULL;

    idx = (idx + 1) % 3;

    /*
     * Allocate the buffer if it's not already allocated.
     */
    if (utf16buf[idx] == NULL) {
        utf16buf_len[idx] = INITIAL_UTFBUF_SIZE;
        utf16buf[idx] = g_malloc(utf16buf_len[idx] * sizeof(wchar_t));
    }

    while (MultiByteToWideChar(CP_UTF8, 0, utf8str, -1, NULL, 0) >= utf16buf_len[idx]) {
        /*
         * Double the buffer's size if it's not big enough.
         * The size of the buffer starts at 128, so doubling its size
         * adds at least another 128 bytes, which is more than enough
         * for one more character plus a terminating '\0'.
         */
        utf16buf_len[idx] *= 2;
        utf16buf[idx] = g_realloc(utf16buf[idx], utf16buf_len[idx] * sizeof(wchar_t));
    }

    if (MultiByteToWideChar(CP_UTF8, 0, utf8str, -1, utf16buf[idx], utf16buf_len[idx]) == 0)
        return NULL;

    return utf16buf[idx];
}

void
utf_8to16_snprintf(TCHAR *utf16buf, int utf16buf_len, const char* fmt, ...)
{
    va_list ap;
    char* dst;

    va_start(ap,fmt);
    dst = ws_strdup_vprintf(fmt, ap);
    va_end(ap);

    StringCchPrintf(utf16buf, utf16buf_len, _T("%s"), utf_8to16(dst));

    g_free(dst);
}

/* Convert from UTF-16 to UTF-8. */
char *
utf_16to8(const wchar_t *utf16str)
{
    static char *utf8buf[3];
    static int utf8buf_len[3];
    static int idx;

    if (utf16str == NULL)
        return NULL;

    idx = (idx + 1) % 3;

    /*
     * Allocate the buffer if it's not already allocated.
    */
    if (utf8buf[idx] == NULL) {
        utf8buf_len[idx] = INITIAL_UTFBUF_SIZE;
        utf8buf[idx] = g_malloc(utf8buf_len[idx]);
    }

    while (WideCharToMultiByte(CP_UTF8, 0, utf16str, -1, NULL, 0, NULL, NULL) >= utf8buf_len[idx]) {
        /*
         * Double the buffer's size if it's not big enough.
         * The size of the buffer starts at 128, so doubling its size
         * adds at least another 128 bytes, which is more than enough
         * for one more character plus a terminating '\0'.
         */
        utf8buf_len[idx] *= 2;
        utf8buf[idx] = g_realloc(utf8buf[idx], utf8buf_len[idx]);
    }

    if (WideCharToMultiByte(CP_UTF8, 0, utf16str, -1, utf8buf[idx], utf8buf_len[idx], NULL, NULL) == 0)
        return NULL;

    return utf8buf[idx];
}

/* Convert our argument list from UTF-16 to UTF-8. */
char **
arg_list_utf_16to8(int argc, wchar_t *wc_argv[]) {
    char **argv;
    int i;

    argv = (char **)g_malloc((argc + 1) * sizeof(char *));
    for (i = 0; i < argc; i++) {
        argv[i] = g_utf16_to_utf8(wc_argv[i], -1, NULL, NULL, NULL);
    }
    argv[argc] = NULL;
    return argv;
}

#endif

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
