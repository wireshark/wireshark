/* charsets.c
 * Routines for handling character sets
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>
#include <glib.h>

#include <epan/proto.h>
#include <epan/wmem_scopes.h>

#include <wsutil/pint.h>
#include <wsutil/unicode-utils.h>

#include "charsets.h"

/*
 * 6-character abbreviation for "Unicode REPLACEMENT CHARACTER", so it
 * takes up the same amount of space as the 6-character hex values for
 * Basic Multilingual Plane code points in the tables below.
 */
#define UNREPL UNICODE_REPLACEMENT_CHARACTER

/* ZERO WIDTH NON-BREAKING SPACE, also known informally as BOM */
#define BYTE_ORDER_MARK 0xFEFF

/*
 * Wikipedia's "Character encoding" template, giving a pile of character
 * encodings and Wikipedia pages for them:
 *
 *    http://en.wikipedia.org/wiki/Template:Character_encoding
 *
 * Unicode character encoding model:
 *
 *    https://www.unicode.org/reports/tr17/
 *
 * International Components for Unicode character set mapping tables:
 *
 *    http://site.icu-project.org/charts/charset
 *
 * MSDN information on code pages:
 *
 *    https://docs.microsoft.com/en-us/windows/win32/intl/code-pages
 *
 * ASCII-based code pages, from IBM:
 *
 *    http://www-01.ibm.com/software/globalization/cp/cp_cpgid.html
 *
 * EBCDIC code pages, from IBM:
 *
 *    http://www-03.ibm.com/systems/i/software/globalization/codepages.html
 *
 * The IBM pages are no longer available; the versions archived on the
 * Wayback Machine are, but the links to the PDF and text versions of
 * the code pages don't all work (do *any* work?).
 *
 * Mappings to Unicode at the Unicode Consortium:
 *
 *    https://www.unicode.org/Public/MAPPINGS/
 *
 * Of note, the VENDORS/MICSFT directory not only has various Windows
 * and DOS code pages, but also several of the common MAC and EBCDIC
 * code page mappings to Unicode.
 */

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as an ASCII string, with all bytes
 * with the high-order bit set being invalid, and return a pointer to a
 * UTF-8 string, allocated using the wmem scope.
 *
 * Octets with the highest bit set will be converted to the Unicode
 * REPLACEMENT CHARACTER.
 */
uint8_t *
get_ascii_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    wmem_strbuf_t *str;
    const uint8_t *prev = ptr;
    size_t valid_bytes = 0;

    str = wmem_strbuf_new_sized(scope, length+1);

    while (length > 0) {
        uint8_t ch = *ptr++;

        if (ch < 0x80) {
            valid_bytes++;
        } else {
            if (valid_bytes) {
                wmem_strbuf_append_len(str, prev, valid_bytes);
                valid_bytes = 0;
            }
            prev = ptr;
            wmem_strbuf_append_unichar_repl(str);
        }
        length--;
    }
    if (valid_bytes) {
        wmem_strbuf_append_len(str, prev, valid_bytes);
    }

    return (uint8_t *) wmem_strbuf_finalize(str);
}

uint8_t *
get_utf_8_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    return ws_utf8_make_valid(scope, ptr, length);
}

/*
 * ISO 646 "Basic code table".
 */
const gunichar2 charset_table_iso_646_basic[0x80] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,        /* 0x00 -      */
    0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,        /*      - 0x0F */
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,        /* 0x10 -      */
    0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f,        /*      - 0x1F */
    0x0020, 0x0021, 0x0022, UNREPL, UNREPL, 0x0025, 0x0026, 0x0027,        /* 0x20 -      */
    0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,        /*      - 0x2F */
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,        /* 0x30 -      */
    0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,        /*      - 0x3F */
    UNREPL, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,        /* 0x40 -      */
    0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,        /*      - 0x4F */
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,        /* 0x50 -      */
    0x0058, 0x0059, 0x005a, UNREPL, UNREPL, UNREPL, UNREPL, 0x005f,        /*      - 0x5F */
    UNREPL, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,        /* 0x60 -      */
    0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,        /*      - 0x6F */
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,        /* 0x70 -      */
    0x0078, 0x0079, 0x007a, UNREPL, UNREPL, UNREPL, UNREPL, 0x007f,        /*      - 0x7F */
};

/*
 * Given a wmem scope, a pointer, a length, and a translation table,
 * treat the string of bytes referred to by the pointer and length as a
 * string encoded using one octet per character, with octets with the
 * high-order bit clear being mapped by the translation table to 2-byte
 * Unicode Basic Multilingual Plane characters (including REPLACEMENT
 * CHARACTER) and octets with the high-order bit set being mapped to
 * REPLACEMENT CHARACTER, and return a pointer to a UTF-8 string,
 * allocated using the wmem scope.
 */
uint8_t *
get_iso_646_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, const gunichar2 table[0x80])
{
    wmem_strbuf_t *str;

    str = wmem_strbuf_new_sized(scope, length+1);

    while (length > 0) {
        uint8_t ch = *ptr;

        if (ch < 0x80)
            wmem_strbuf_append_unichar(str, table[ch]);
        else
            wmem_strbuf_append_unichar_repl(str);
        ptr++;
        length--;
    }

    return (uint8_t *) wmem_strbuf_finalize(str);
}

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as an ISO 8859/1 string, and
 * return a pointer to a UTF-8 string, allocated using the wmem scope.
 */
uint8_t *
get_8859_1_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    wmem_strbuf_t *str;

    str = wmem_strbuf_new_sized(scope, length+1);

    while (length > 0) {
        uint8_t ch = *ptr;

        if (ch < 0x80)
            wmem_strbuf_append_c(str, ch);
        else {
            /*
             * Note: we assume here that the code points
             * 0x80-0x9F are used for C1 control characters,
             * and thus have the same value as the corresponding
             * Unicode code points.
             */
            wmem_strbuf_append_unichar(str, ch);
        }
        ptr++;
        length--;
    }

    return (uint8_t *) wmem_strbuf_finalize(str);
}

/*
 * Translation tables that map the upper 128 code points in single-byte
 * "extended ASCII" character encodings to Unicode code points in the
 * Basic Multilingual Plane.
 */

/* ISO-8859-2 (https://en.wikipedia.org/wiki/ISO/IEC_8859-2#Code_page_layout) */
const gunichar2 charset_table_iso_8859_2[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0104, 0x02d8, 0x0141, 0x00a4, 0x013d, 0x015a, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x0160, 0x015e, 0x0164, 0x0179, 0x00ad, 0x017d, 0x017b,        /*      - 0xAF */
    0x00b0, 0x0105, 0x02db, 0x0142, 0x00b4, 0x013e, 0x015b, 0x02c7,        /* 0xB0 -      */
    0x00b8, 0x0161, 0x015f, 0x0165, 0x017a, 0x02dd, 0x017e, 0x017c,        /*      - 0xBF */
    0x0154, 0x00c1, 0x00c2, 0x0102, 0x00c4, 0x0139, 0x0106, 0x00c7,        /* 0xC0 -      */
    0x010c, 0x00c9, 0x0118, 0x00cb, 0x011a, 0x00cd, 0x00ce, 0x010e,        /*      - 0xCF */
    0x0110, 0x0143, 0x0147, 0x00d3, 0x00d4, 0x0150, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x0158, 0x016e, 0x00da, 0x0170, 0x00dc, 0x00dd, 0x0162, 0x00df,        /*      - 0xDF */
    0x0155, 0x00e1, 0x00e2, 0x0103, 0x00e4, 0x013a, 0x0107, 0x00e7,        /* 0xE0 -      */
    0x010d, 0x00e9, 0x0119, 0x00eb, 0x011b, 0x00ed, 0x00ee, 0x010f,        /*      - 0xEF */
    0x0111, 0x0144, 0x0148, 0x00f3, 0x00f4, 0x0151, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x0159, 0x016f, 0x00fa, 0x0171, 0x00fc, 0x00fd, 0x0163, 0x02d9         /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-3 */
const gunichar2 charset_table_iso_8859_3[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0126, 0x02d8, 0x00a3, 0x00a4, UNREPL, 0x0124, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x0130, 0x015e, 0x011e, 0x0134, 0x00ad, UNREPL, 0x017b,        /*      - 0xAF */
    0x00b0, 0x0127, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x0125, 0x00b7,        /* 0xB0 -      */
    0x00b8, 0x0131, 0x015f, 0x011f, 0x0135, 0x00bd, UNREPL, 0x017c,        /*      - 0xBF */
    0x00c0, 0x00c1, 0x00c2, UNREPL, 0x00c4, 0x010a, 0x0108, 0x00c7,        /* 0xC0 -      */
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    UNREPL, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x0120, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x011c, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x016c, 0x015c, 0x00df,        /*      - 0xDF */
    0x00e0, 0x00e1, 0x00e2, UNREPL, 0x00e4, 0x010b, 0x0109, 0x00e7,        /* 0xE0 -      */
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    UNREPL, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x0121, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x011d, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x016d, 0x015d, 0x02d9,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-4 */
const gunichar2 charset_table_iso_8859_4[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0104, 0x0138, 0x0156, 0x00a4, 0x0128, 0x013b, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x0160, 0x0112, 0x0122, 0x0166, 0x00ad, 0x017d, 0x00af,        /*      - 0xAF */
    0x00b0, 0x0105, 0x02db, 0x0157, 0x00b4, 0x0129, 0x013c, 0x02c7,        /* 0xB0 -      */
    0x00b8, 0x0161, 0x0113, 0x0123, 0x0167, 0x014a, 0x017e, 0x014b,        /*      - 0xBF */
    0x0100, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x012e,        /* 0xC0 -      */
    0x010c, 0x00c9, 0x0118, 0x00cb, 0x0116, 0x00cd, 0x00ce, 0x012a,        /*      - 0xCF */
    0x0110, 0x0145, 0x014c, 0x0136, 0x00d4, 0x00d5, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x00d8, 0x0172, 0x00da, 0x00db, 0x00dc, 0x0168, 0x016a, 0x00df,        /*      - 0xDF */
    0x0101, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x012f,        /* 0xE0 -      */
    0x010d, 0x00e9, 0x0119, 0x00eb, 0x0117, 0x00ed, 0x00ee, 0x012b,        /*      - 0xEF */
    0x0111, 0x0146, 0x014d, 0x0137, 0x00f4, 0x00f5, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x00f8, 0x0173, 0x00fa, 0x00fb, 0x00fc, 0x0169, 0x016b, 0x02d9,        /*      - 0xFF */
};

/* ISO-8859-5 (https://en.wikipedia.org/wiki/ISO/IEC_8859-5#Code_page_layout) */
const gunichar2 charset_table_iso_8859_5[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0406, 0x0407,        /* 0xA0 -      */
    0x0408, 0x0409, 0x040a, 0x040b, 0x040c, 0x040d, 0x040e, 0x040f,        /*      - 0xAF */
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,        /* 0xB0 -      */
    0x0418, 0x0419, 0x041a, 0x041b, 0x041c, 0x041d, 0x041e, 0x041f,        /*      - 0xBF */
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,        /* 0xC0 -      */
    0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f,        /*      - 0xCF */
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,        /* 0xD0 -      */
    0x0438, 0x0439, 0x043a, 0x043b, 0x043c, 0x043d, 0x043e, 0x043f,        /*      - 0xDF */
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,        /* 0xE0 -      */
    0x0448, 0x0449, 0x044a, 0x044b, 0x044c, 0x044d, 0x044e, 0x044f,        /*      - 0xEF */
    0x2116, 0x0451, 0x0452, 0x0453, 0x0454, 0x0455, 0x0456, 0x0457,        /* 0xF0 -      */
    0x0458, 0x0459, 0x045a, 0x045b, 0x045c, 0x00a7, 0x045e, 0x045f         /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-6 */
const gunichar2 charset_table_iso_8859_6[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, UNREPL, UNREPL, UNREPL, 0x00a4, UNREPL, UNREPL, UNREPL,        /* 0xA0 -      */
    UNREPL, UNREPL, UNREPL, UNREPL, 0x060c, 0x00ad, UNREPL, UNREPL,        /*      - 0xAF */
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /* 0xB0 -      */
    UNREPL, UNREPL, UNREPL, 0x061b, UNREPL, UNREPL, UNREPL, 0x061f,        /*      - 0xBF */
    UNREPL, 0x0621, 0x0622, 0x0623, 0x0624, 0x0625, 0x0626, 0x0627,        /* 0xC0 -      */
    0x0628, 0x0629, 0x062a, 0x062b, 0x062c, 0x062d, 0x062e, 0x062f,        /*      - 0xCF */
    0x0630, 0x0631, 0x0632, 0x0633, 0x0634, 0x0635, 0x0636, 0x0637,        /* 0xD0 -      */
    0x0638, 0x0639, 0x063a, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /*      - 0xDF */
    0x0640, 0x0641, 0x0642, 0x0643, 0x0644, 0x0645, 0x0646, 0x0647,        /* 0xE0 -      */
    0x0648, 0x0649, 0x064a, 0x064b, 0x064c, 0x064d, 0x064e, 0x064f,        /*      - 0xEF */
    0x0650, 0x0651, 0x0652, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /* 0xF0 -      */
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-7 */
const gunichar2 charset_table_iso_8859_7[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x2018, 0x2019, 0x00a3, 0x20ac, 0x20af, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x00a9, 0x037a, 0x00ab, 0x00ac, 0x00ad, UNREPL, 0x2015,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x0384, 0x0385, 0x0386, 0x00b7,        /* 0xB0 -      */
    0x0388, 0x0389, 0x038a, 0x00bb, 0x038c, 0x00bd, 0x038e, 0x038f,        /*      - 0xBF */
    0x0390, 0x0391, 0x0392, 0x0393, 0x0394, 0x0395, 0x0396, 0x0397,        /* 0xC0 -      */
    0x0398, 0x0399, 0x039a, 0x039b, 0x039c, 0x039d, 0x039e, 0x039f,        /*      - 0xCF */
    0x03a0, 0x03a1, UNREPL, 0x03a3, 0x03a4, 0x03a5, 0x03a6, 0x03a7,        /* 0xD0 -      */
    0x03a8, 0x03a9, 0x03aa, 0x03ab, 0x03ac, 0x03ad, 0x03ae, 0x03af,        /*      - 0xDF */
    0x03b0, 0x03b1, 0x03b2, 0x03b3, 0x03b4, 0x03b5, 0x03b6, 0x03b7,        /* 0xE0 -      */
    0x03b8, 0x03b9, 0x03ba, 0x03bb, 0x03bc, 0x03bd, 0x03be, 0x03bf,        /*      - 0xEF */
    0x03c0, 0x03c1, 0x03c2, 0x03c3, 0x03c4, 0x03c5, 0x03c6, 0x03c7,        /* 0xF0 -      */
    0x03c8, 0x03c9, 0x03ca, 0x03cb, 0x03cc, 0x03cd, 0x03ce, UNREPL,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-8 */
const gunichar2 charset_table_iso_8859_8[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, UNREPL, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x00a9, 0x00d7, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x00b8, 0x00b9, 0x00f7, 0x00bb, 0x00bc, 0x00bd, 0x00be, UNREPL,        /*      - 0xBF */
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /* 0xC0 -      */
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /*      - 0xCF */
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,        /* 0xD0 -      */
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, 0x2017,        /*      - 0xDF */
    0x05d0, 0x05d1, 0x05d2, 0x05d3, 0x05d4, 0x05d5, 0x05d6, 0x05d7,        /* 0xE0 -      */
    0x05d8, 0x05d9, 0x05da, 0x05db, 0x05dc, 0x05dd, 0x05de, 0x05df,        /*      - 0xEF */
    0x05e0, 0x05e1, 0x05e2, 0x05e3, 0x05e4, 0x05e5, 0x05e6, 0x05e7,        /* 0xF0 -      */
    0x05e8, 0x05e9, 0x05ea, UNREPL, UNREPL, 0x200e, 0x200f, UNREPL,        /*      - 0xFF */
};

/* ISO-8859-9 (https://en.wikipedia.org/wiki/ISO/IEC_8859-9#Code_page_layout) */
const gunichar2 charset_table_iso_8859_9[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,        /*      - 0xBF */
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,        /* 0xC0 -      */
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    0x011e, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x0130, 0x015e, 0x00df,        /*      - 0xDF */
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,        /* 0xE0 -      */
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    0x011f, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x0131, 0x015f, 0x00ff         /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-10 */
const gunichar2 charset_table_iso_8859_10[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0104, 0x0112, 0x0122, 0x012a, 0x0128, 0x0136, 0x00a7,        /* 0xA0 -      */
    0x013b, 0x0110, 0x0160, 0x0166, 0x017d, 0x00ad, 0x016a, 0x014a,        /*      - 0xAF */
    0x00b0, 0x0105, 0x0113, 0x0123, 0x012b, 0x0129, 0x0137, 0x00b7,        /* 0xB0 -      */
    0x013c, 0x0111, 0x0161, 0x0167, 0x017e, 0x2015, 0x016b, 0x014b,        /*      - 0xBF */
    0x0100, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x012e,        /* 0xC0 -      */
    0x010c, 0x00c9, 0x0118, 0x00cb, 0x0116, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    0x00d0, 0x0145, 0x014c, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x0168,        /* 0xD0 -      */
    0x00d8, 0x0172, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,        /*      - 0xDF */
    0x0101, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x012f,        /* 0xE0 -      */
    0x010d, 0x00e9, 0x0119, 0x00eb, 0x0117, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    0x00f0, 0x0146, 0x014d, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x0169,        /* 0xF0 -      */
    0x00f8, 0x0173, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x0138,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-11 */
const gunichar2 charset_table_iso_8859_11[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0e01, 0x0e02, 0x0e03, 0x0e04, 0x0e05, 0x0e06, 0x0e07,        /* 0xA0 -      */
    0x0e08, 0x0e09, 0x0e0a, 0x0e0b, 0x0e0c, 0x0e0d, 0x0e0e, 0x0e0f,        /*      - 0xAF */
    0x0e10, 0x0e11, 0x0e12, 0x0e13, 0x0e14, 0x0e15, 0x0e16, 0x0e17,        /* 0xB0 -      */
    0x0e18, 0x0e19, 0x0e1a, 0x0e1b, 0x0e1c, 0x0e1d, 0x0e1e, 0x0e1f,        /*      - 0xBF */
    0x0e20, 0x0e21, 0x0e22, 0x0e23, 0x0e24, 0x0e25, 0x0e26, 0x0e27,        /* 0xC0 -      */
    0x0e28, 0x0e29, 0x0e2a, 0x0e2b, 0x0e2c, 0x0e2d, 0x0e2e, 0x0e2f,        /*      - 0xCF */
    0x0e30, 0x0e31, 0x0e32, 0x0e33, 0x0e34, 0x0e35, 0x0e36, 0x0e37,        /* 0xD0 -      */
    0x0e38, 0x0e39, 0x0e3a, UNREPL, UNREPL, UNREPL, UNREPL, 0x0e3f,        /*      - 0xDF */
    0x0e40, 0x0e41, 0x0e42, 0x0e43, 0x0e44, 0x0e45, 0x0e46, 0x0e47,        /* 0xE0 -      */
    0x0e48, 0x0e49, 0x0e4a, 0x0e4b, 0x0e4c, 0x0e4d, 0x0e4e, 0x0e4f,        /*      - 0xEF */
    0x0e50, 0x0e51, 0x0e52, 0x0e53, 0x0e54, 0x0e55, 0x0e56, 0x0e57,        /* 0xF0 -      */
    0x0e58, 0x0e59, 0x0e5a, 0x0e5b, UNREPL, UNREPL, UNREPL, UNREPL,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-13 */
const gunichar2 charset_table_iso_8859_13[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x201d, 0x00a2, 0x00a3, 0x00a4, 0x201e, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x00d8, 0x00a9, 0x0156, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00c6,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x201c, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x00f8, 0x00b9, 0x0157, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00e6,        /*      - 0xBF */
    0x0104, 0x012e, 0x0100, 0x0106, 0x00c4, 0x00c5, 0x0118, 0x0112,        /* 0xC0 -      */
    0x010c, 0x00c9, 0x0179, 0x0116, 0x0122, 0x0136, 0x012a, 0x013b,        /*      - 0xCF */
    0x0160, 0x0143, 0x0145, 0x00d3, 0x014c, 0x00d5, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x0172, 0x0141, 0x015a, 0x016a, 0x00dc, 0x017b, 0x017d, 0x00df,        /*      - 0xDF */
    0x0105, 0x012f, 0x0101, 0x0107, 0x00e4, 0x00e5, 0x0119, 0x0113,        /* 0xE0 -      */
    0x010d, 0x00e9, 0x017a, 0x0117, 0x0123, 0x0137, 0x012b, 0x013c,        /*      - 0xEF */
    0x0161, 0x0144, 0x0146, 0x00f3, 0x014d, 0x00f5, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x0173, 0x0142, 0x015b, 0x016b, 0x00fc, 0x017c, 0x017e, 0x2019,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-14 */
const gunichar2 charset_table_iso_8859_14[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x1e02, 0x1e03, 0x00a3, 0x010a, 0x010b, 0x1e0a, 0x00a7,        /* 0xA0 -      */
    0x1e80, 0x00a9, 0x1e82, 0x1e0b, 0x1ef2, 0x00ad, 0x00ae, 0x0178,        /*      - 0xAF */
    0x1e1e, 0x1e1f, 0x0120, 0x0121, 0x1e40, 0x1e41, 0x00b6, 0x1e56,        /* 0xB0 -      */
    0x1e81, 0x1e57, 0x1e83, 0x1e60, 0x1ef3, 0x1e84, 0x1e85, 0x1e61,        /*      - 0xBF */
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,        /* 0xC0 -      */
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    0x0174, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x1e6a,        /* 0xD0 -      */
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x0176, 0x00df,        /*      - 0xDF */
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,        /* 0xE0 -      */
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    0x0175, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x1e6b,        /* 0xF0 -      */
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x0177, 0x00ff,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-15 */
const gunichar2 charset_table_iso_8859_15[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x20ac, 0x00a5, 0x0160, 0x00a7,        /* 0xA0 -      */
    0x0161, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x017d, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x017e, 0x00b9, 0x00ba, 0x00bb, 0x0152, 0x0153, 0x0178, 0x00bf,        /*      - 0xBF */
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,        /* 0xC0 -      */
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,        /*      - 0xDF */
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,        /* 0xE0 -      */
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,        /*      - 0xFF */
};

/* generated by ../tools/make_charset_ISO-8859-16 */
const gunichar2 charset_table_iso_8859_16[0x80] = {
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,        /* 0x80 -      */
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,        /*      - 0x8F */
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,        /* 0x90 -      */
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,        /*      - 0x9F */
    0x00a0, 0x0104, 0x0105, 0x0141, 0x20ac, 0x201e, 0x0160, 0x00a7,        /* 0xA0 -      */
    0x0161, 0x00a9, 0x0218, 0x00ab, 0x0179, 0x00ad, 0x017a, 0x017b,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x010c, 0x0142, 0x017d, 0x201d, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x017e, 0x010d, 0x0219, 0x00bb, 0x0152, 0x0153, 0x0178, 0x017c,        /*      - 0xBF */
    0x00c0, 0x00c1, 0x00c2, 0x0102, 0x00c4, 0x0106, 0x00c6, 0x00c7,        /* 0xC0 -      */
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    0x0110, 0x0143, 0x00d2, 0x00d3, 0x00d4, 0x0150, 0x00d6, 0x015a,        /* 0xD0 -      */
    0x0170, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x0118, 0x021a, 0x00df,        /*      - 0xDF */
    0x00e0, 0x00e1, 0x00e2, 0x0103, 0x00e4, 0x0107, 0x00e6, 0x00e7,        /* 0xE0 -      */
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    0x0111, 0x0144, 0x00f2, 0x00f3, 0x00f4, 0x0151, 0x00f6, 0x015b,        /* 0xF0 -      */
    0x0171, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x0119, 0x021b, 0x00ff,        /*      - 0xFF */
};

/*
 * Windows-1250
 *
 * See:
 *     httpss://en.wikipedia.org/wiki/Windows-1250)
 *     https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1250.TXT
 */
const gunichar2 charset_table_cp1250[0x80] = {
    0x20ac, UNREPL, 0x201a, UNREPL, 0x201e, 0x2026, 0x2020, 0x2021,        /* 0x80 -      */
    UNREPL, 0x2030, 0x0160, 0x2039, 0x015a, 0x0164, 0x017d, 0x0179,        /*      - 0x8F */
    UNREPL, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,        /* 0x90 -      */
    UNREPL, 0x2122, 0x0161, 0x203a, 0x015b, 0x0165, 0x017e, 0x017a,        /*      - 0x9F */
    0x00a0, 0x02c7, 0x02d8, 0x0141, 0x00a4, 0x0104, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x00a9, 0x015e, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x017b,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x02db, 0x0142, 0x00b4, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x00b8, 0x0105, 0x015f, 0x00bb, 0x013d, 0x02dd, 0x013e, 0x017c,        /*      - 0xBF */
    0x0154, 0x00c1, 0x00c2, 0x0102, 0x00c4, 0x0139, 0x0106, 0x00c7,        /* 0xC0 -      */
    0x010c, 0x00c9, 0x0118, 0x00cb, 0x011a, 0x00cd, 0x00ce, 0x010e,        /*      - 0xCF */
    0x0110, 0x0143, 0x0147, 0x00d3, 0x00d4, 0x0150, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x0158, 0x016e, 0x00da, 0x0170, 0x00dc, 0x00dd, 0x0162, 0x00df,        /*      - 0xDF */
    0x0155, 0x00e1, 0x00e2, 0x0103, 0x00e4, 0x013a, 0x0107, 0x00e7,        /* 0xE0 -      */
    0x010d, 0x00e9, 0x0119, 0x00eb, 0x011b, 0x00ed, 0x00ee, 0x010f,        /*      - 0xEF */
    0x0111, 0x0144, 0x0148, 0x00f3, 0x00f4, 0x0151, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x0159, 0x016f, 0x00fa, 0x0171, 0x00fc, 0x00fd, 0x0163, 0x02d9,        /*      - 0xFF */
};

/*
 * Windows-1251
 *
 * See:
 *     https://en.wikipedia.org/wiki/Windows-1251
 *     https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1251.TXT
 */
const gunichar2 charset_table_cp1251[0x80] = {
    0x0402, 0x0403, 0x201a, 0x0453, 0x201e, 0x2026, 0x2020, 0x2021,        /* 0x80 -      */
    0x20ac, 0x2030, 0x0409, 0x2039, 0x040a, 0x040c, 0x040B, 0x040f,        /*      - 0x8F */
    0x0452, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,        /* 0x90 -      */
    UNREPL, 0x2122, 0x0459, 0x203a, 0x045a, 0x045c, 0x045b, 0x045f,        /*      - 0x9F */
    0x00a0, 0x040e, 0x045e, 0x0408, 0x00a4, 0x0490, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x0401, 0x00a9, 0x0404, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x0407,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x0406, 0x0456, 0x0491, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x0451, 0x2116, 0x0454, 0x00bb, 0x0458, 0x0405, 0x0455, 0x0457,        /*      - 0xBF */
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,        /* 0xC0 -      */
    0x0418, 0x0419, 0x041a, 0x041b, 0x041c, 0x041d, 0x041e, 0x041f,        /*      - 0xCF */
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,        /* 0xD0 -      */
    0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f,        /*      - 0xDF */
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,        /* 0xE0 -      */
    0x0438, 0x0439, 0x043a, 0x043b, 0x043c, 0x043d, 0x043e, 0x043f,        /*      - 0xEF */
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,        /* 0xF0 -      */
    0x0448, 0x0449, 0x044a, 0x044b, 0x044c, 0x044d, 0x044e, 0x044f,        /*      - 0xFF */
};

/*
 * Windows-1252
 *
 * See:
 *     https://en.wikipedia.org/wiki/Windows-1252
 *     https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT
 */
const gunichar2 charset_table_cp1252[0x80] = {
    0x20ac, UNREPL, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,        /* 0x80 -      */
    0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, UNREPL, 0x0172, UNREPL,        /*      - 0x8F */
    UNREPL, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,        /* 0x90 -      */
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, UNREPL, 0x0173, 0x0178,        /*      - 0x9F */
    0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,        /* 0xA0 -      */
    0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,        /*      - 0xAF */
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,        /* 0xB0 -      */
    0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,        /*      - 0xBF */
    0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,        /* 0xC0 -      */
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,        /*      - 0xCF */
    0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,        /* 0xD0 -      */
    0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,        /*      - 0xDF */
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,        /* 0xE0 -      */
    0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,        /*      - 0xEF */
    0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,        /* 0xF0 -      */
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,        /*      - 0xFF */
};

/* generated by ./make_charset_table MACROMAN */
/* That's "MacRoman", not "Macro Man" (faster than a speeding recursive expansion!) */
const gunichar2 charset_table_mac_roman[0x80] = {
    0x00c4, 0x00c5, 0x00c7, 0x00c9, 0x00d1, 0x00d6, 0x00dc, 0x00e1,        /* 0x80 -      */
    0x00e0, 0x00e2, 0x00e4, 0x00e3, 0x00e5, 0x00e7, 0x00e9, 0x00e8,        /*      - 0x8F */
    0x00ea, 0x00eb, 0x00ed, 0x00ec, 0x00ee, 0x00ef, 0x00f1, 0x00f3,        /* 0x90 -      */
    0x00f2, 0x00f4, 0x00f6, 0x00f5, 0x00fa, 0x00f9, 0x00fb, 0x00fc,        /*      - 0x9F */
    0x2020, 0x00b0, 0x00a2, 0x00a3, 0x00a7, 0x2022, 0x00b6, 0x00df,        /* 0xA0 -      */
    0x00ae, 0x00a9, 0x2122, 0x00b4, 0x00a8, 0x2260, 0x00c6, 0x00d8,        /*      - 0xAF */
    0x221e, 0x00b1, 0x2264, 0x2265, 0x00a5, 0x00b5, 0x2202, 0x2211,        /* 0xB0 -      */
    0x220f, 0x03c0, 0x222b, 0x00aa, 0x00ba, 0x03a9, 0x00e6, 0x00f8,        /*      - 0xBF */
    0x00bf, 0x00a1, 0x00ac, 0x221a, 0x0192, 0x2248, 0x2206, 0x00ab,        /* 0xC0 -      */
    0x00bb, 0x2026, 0x00a0, 0x00c0, 0x00c3, 0x00d5, 0x0152, 0x0153,        /*      - 0xCF */
    0x2013, 0x2014, 0x201c, 0x201d, 0x2018, 0x2019, 0x00f7, 0x25ca,        /* 0xD0 -      */
    0x00ff, 0x0178, 0x2044, 0x20ac, 0x2039, 0x203a, 0xfb01, 0xfb02,        /*      - 0xDF */
    0x2021, 0x00b7, 0x201a, 0x201e, 0x2030, 0x00c2, 0x00ca, 0x00c1,        /* 0xE0 -      */
    0x00cb, 0x00c8, 0x00cd, 0x00ce, 0x00cf, 0x00cc, 0x00d3, 0x00d4,        /*      - 0xEF */
    0xf8ff, 0x00d2, 0x00da, 0x00db, 0x00d9, 0x0131, 0x02c6, 0x02dc,        /* 0xF0 -      */
    0x00af, 0x02d8, 0x02d9, 0x02da, 0x00b8, 0x02dd, 0x02db, 0x02c7,        /*      - 0xFF */
};

/* generated by ./make_charset_table CP437 */
const gunichar2 charset_table_cp437[0x80] = {
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7,        /* 0x80 -      */
    0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,        /*      - 0x8F */
    0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,        /* 0x90 -      */
    0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192,        /*      - 0x9F */
    0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,        /* 0xA0 -      */
    0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,        /*      - 0xAF */
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,        /* 0xB0 -      */
    0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,        /*      - 0xBF */
    0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,        /* 0xC0 -      */
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,        /*      - 0xCF */
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,        /* 0xD0 -      */
    0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,        /*      - 0xDF */
    0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4,        /* 0xE0 -      */
    0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,        /*      - 0xEF */
    0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,        /* 0xF0 -      */
    0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0,        /*      - 0xFF */
};

/*
 * CP855
 *
 * See
 *     https://en.wikipedia.org/wiki/CP855
 *     https://unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP855.TXT
 *
 * XXX - this doesn't have the graphics for 0x00 through 0x1F shown
 * on the Wikipedia page, but not in the Microsoft mapping file;
 * that would require a 256-code-point mapping table.  (Are those
 * positions used for the same graphics on all code pages - the PC
 * graphics set, or whatever it's called?)
 */
const gunichar2 charset_table_cp855[0x80] = {
    0x0452, 0x0402, 0x0453, 0x0403, 0x0451, 0x0401, 0x0454, 0x0404,        /* 0x80 -      */
    0x0455, 0x0405, 0x0456, 0x0406, 0x0457, 0x0407, 0x0458, 0x0408,        /*      - 0x8F */
    0x0459, 0x0409, 0x045a, 0x040a, 0x045b, 0x040b, 0x045c, 0x040c,        /* 0x90 -      */
    0x045e, 0x040e, 0x045f, 0x040f, 0x044e, 0x042e, 0x044a, 0x042a,        /*      - 0x9F */
    0x0430, 0x0410, 0x0431, 0x0411, 0x0446, 0x0426, 0x0434, 0x0414,        /* 0xA0 -      */
    0x0435, 0x0415, 0x0444, 0x0424, 0x0433, 0x0413, 0x00ab, 0x00bb,        /*      - 0xAF */
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x0445, 0x0425, 0x0438,        /* 0xB0 -      */
    0x0418, 0x2563, 0x2551, 0x2557, 0x2550, 0x0439, 0x0419, 0x2510,        /*      - 0xBF */
    0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x043a, 0x041a,        /* 0xC0 -      */
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x00a4,        /*      - 0xCF */
    0x043b, 0x041b, 0x043c, 0x041c, 0x043d, 0x041d, 0x043e, 0x041e,        /* 0xD0 -      */
    0x043f, 0x2518, 0x250c, 0x2588, 0x2584, 0x041f, 0x044f, 0x2580,        /*      - 0xDF */
    0x042f, 0x0440, 0x0420, 0x0441, 0x0421, 0x0442, 0x0422, 0x0443,        /* 0xE0 -      */
    0x0423, 0x0436, 0x0416, 0x0432, 0x0412, 0x044c, 0x042c, 0x2116,        /*      - 0xEF */
    0x00ad, 0x044b, 0x042b, 0x0437, 0x0417, 0x0448, 0x0428, 0x044d,        /* 0xF0 -      */
    0x042d, 0x0449, 0x0429, 0x0447, 0x0427, 0x00a7, 0x25a0, 0x00a0,        /*      - 0xFF */
};

/*
 * CP866
 *
 * See:
 *     https://en.wikipedia.org/wiki/CP866
 *     https://unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP866.TXT
 */
const gunichar2 charset_table_cp866[0x80] = {
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,        /* 0x80 -      */
    0x0418, 0x0419, 0x041A, 0x041b, 0x041c, 0x041d, 0x041e, 0x041f,        /*      - 0x8F */
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,        /* 0x90 -      */
    0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f,        /*      - 0x9F */
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,        /* 0xA0 -      */
    0x0438, 0x0439, 0x043a, 0x043b, 0x043c, 0x043d, 0x043e, 0x043f,        /*      - 0xAF */
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,        /* 0xB0 -      */
    0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,        /*      - 0xBF */
    0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,        /* 0xC0 -      */
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567,        /*      - 0xCF */
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,        /* 0xD0 -      */
    0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,        /*      - 0xDF */
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,        /* 0xE0 -      */
    0x0448, 0x0449, 0x044a, 0x044b, 0x044c, 0x044d, 0x044e, 0x044f,        /*      - 0xEF */
    0x0401, 0x0451, 0x0404, 0x0454, 0x0407, 0x0457, 0x040e, 0x045e,        /* 0xF0 -      */
    0x00b0, 0x2219, 0x00b7, 0x221a, 0x2216, 0x00a4, 0x25a0, 0x00a0,        /*      - 0xFF */
};

/*
 * Given a wmem scope, a pointer, a length, and a translation table with
 * 128 entries, treat the string of bytes referred to by the pointer and
 * length as a string encoded using one octet per character, with octets
 * with the high-order bit clear being ASCII and octets with the high-order
 * bit set being mapped by the translation table to 2-byte Unicode Basic
 * Multilingual Plane characters (including REPLACEMENT CHARACTER), and
 * return a pointer to a UTF-8 string, allocated using the wmem scope.
 */
uint8_t *
get_unichar2_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, const gunichar2 table[0x80])
{
    wmem_strbuf_t *str;

    str = wmem_strbuf_new_sized(scope, length+1);

    while (length > 0) {
        uint8_t ch = *ptr;

        if (ch < 0x80)
            wmem_strbuf_append_c(str, ch);
        else
            wmem_strbuf_append_unichar(str, table[ch-0x80]);
        ptr++;
        length--;
    }

    return (uint8_t *) wmem_strbuf_finalize(str);
}

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UCS-2 encoded string
 * containing characters from the Basic Multilingual Plane (plane 0) of
 * Unicode, and return a pointer to a UTF-8 string, allocated with the
 * wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN,
 * possibly ORed with ENC_BOM.
 *
 * Specify length in bytes.
 */
uint8_t *
get_ucs_2_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, unsigned encoding)
{
    gunichar2      uchar;
    int            i = 0;       /* Byte counter for string */
    wmem_strbuf_t *strbuf;

    strbuf = wmem_strbuf_new_sized(scope, length+1);

    if (encoding & ENC_BOM && length >= 2) {
        if (pletoh16(ptr) == BYTE_ORDER_MARK) {
            encoding = ENC_LITTLE_ENDIAN;
            i += 2;
        } else if (pntoh16(ptr) == BYTE_ORDER_MARK) {
            encoding = ENC_BIG_ENDIAN;
            i += 2;
        }
    }

    encoding = encoding & ENC_LITTLE_ENDIAN;

    for(; i + 1 < length; i += 2) {
        if (encoding == ENC_BIG_ENDIAN) {
            uchar = pntoh16(ptr + i);
        } else {
            uchar = pletoh16(ptr + i);
        }
        wmem_strbuf_append_unichar_validated(strbuf, uchar);
    }

    /*
     * If i < length, this means we were handed an odd number of bytes;
     * insert a REPLACEMENT CHARACTER to mark the error.
     */
    if (i < length) {
        wmem_strbuf_append_unichar_repl(strbuf);
    }
    return (uint8_t *) wmem_strbuf_finalize(strbuf);
}

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UTF-16 encoded string, and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 *
 * See RFC 2781 section 2.2.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN,
 * possibly ORed with ENC_BOM.
 *
 * Specify length in bytes.
 */
uint8_t *
get_utf_16_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, unsigned encoding)
{
    wmem_strbuf_t *strbuf;
    gunichar2      uchar2, lead_surrogate;
    gunichar       uchar;
    int            i = 0;       /* Byte counter for string */

    strbuf = wmem_strbuf_new_sized(scope, length+1);

    if (encoding & ENC_BOM && length >= 2) {
        if (pletoh16(ptr) == BYTE_ORDER_MARK) {
            encoding = ENC_LITTLE_ENDIAN;
            i += 2;
        } else if (pntoh16(ptr) == BYTE_ORDER_MARK) {
            encoding = ENC_BIG_ENDIAN;
            i += 2;
        }
    }

    encoding = encoding & ENC_LITTLE_ENDIAN;

    for(; i + 1 < length; i += 2) {
        if (encoding == ENC_BIG_ENDIAN)
            uchar2 = pntoh16(ptr + i);
        else
            uchar2 = pletoh16(ptr + i);

        if (IS_LEAD_SURROGATE(uchar2)) {
            /*
             * Lead surrogate.  Must be followed by
             * a trail surrogate.
             */
            i += 2;
            if (i + 1 >= length) {
                /*
                 * Oops, string ends with a lead surrogate.
                 *
                 * Insert a REPLACEMENT CHARACTER to mark the error,
                 * and quit.
                 */
                wmem_strbuf_append_unichar(strbuf, UNREPL);
                break;
            }
            lead_surrogate = uchar2;
            if (encoding == ENC_BIG_ENDIAN)
                uchar2 = pntoh16(ptr + i);
            else
                uchar2 = pletoh16(ptr + i);
            if (IS_TRAIL_SURROGATE(uchar2)) {
                /* Trail surrogate. */
                uchar = SURROGATE_VALUE(lead_surrogate, uchar2);
                wmem_strbuf_append_unichar(strbuf, uchar);
            } else {
                /*
                 * Not a trail surrogate.
                 *
                 * Insert a REPLACEMENT CHARACTER to mark the error,
                 * and continue;
                 */
                wmem_strbuf_append_unichar(strbuf, UNREPL);
            }
        } else {
            if (IS_TRAIL_SURROGATE(uchar2)) {
                /*
                 * Trail surrogate without a preceding
                 * lead surrogate.
                 *
                 * Insert a REPLACEMENT CHARACTER to mark the error,
                 * and continue;
                 */
                wmem_strbuf_append_unichar(strbuf, UNREPL);
            } else {
                /*
                 * Non-surrogate; just append it.
                 */
                wmem_strbuf_append_unichar(strbuf, uchar2);
            }
        }
    }

    /*
     * If i < length, this means we were handed an odd number of bytes,
     * so we're not a valid UTF-16 string; insert a REPLACEMENT CHARACTER
     * to mark the error.
     */
    if (i < length)
        wmem_strbuf_append_unichar(strbuf, UNREPL);
    return (uint8_t *) wmem_strbuf_finalize(strbuf);
}

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UCS-4 encoded string, and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN
 *
 * Specify length in bytes
 */
uint8_t *
get_ucs_4_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, unsigned encoding)
{
    gunichar       uchar;
    int            i = 0;       /* Byte counter for string */
    wmem_strbuf_t *strbuf;

    strbuf = wmem_strbuf_new_sized(scope, length+1);

    if (encoding & ENC_BOM && length >= 4) {
        if (pletoh32(ptr) == BYTE_ORDER_MARK) {
            encoding = ENC_LITTLE_ENDIAN;
            i += 4;
        } else if (pntoh32(ptr) == BYTE_ORDER_MARK) {
            encoding = ENC_BIG_ENDIAN;
            i += 4;
        }
    }

    encoding = encoding & ENC_LITTLE_ENDIAN;

    for(; i + 3 < length; i += 4) {
        if (encoding == ENC_BIG_ENDIAN)
            uchar = pntoh32(ptr + i);
        else
            uchar = pletoh32(ptr + i);

        wmem_strbuf_append_unichar_validated(strbuf, uchar);
    }

    /*
     * if i < length, this means we were handed a number of bytes
     * that's not a multiple of 4, so not a valid UCS-4 string.
     * Insert a REPLACEMENT CHARACTER for the remaining bytes.
     */
    if (i < length) {
        wmem_strbuf_append_unichar(strbuf, UNREPL);
    }
    return (uint8_t *)wmem_strbuf_finalize(strbuf);
}

/*
 * FROM GNOKII
 * gsm-encoding.c
 * gsm-sms.c
 */

/* ETSI GSM 03.38, version 6.0.1, section 6.2.1; Default alphabet */
static const gunichar2 gsm_default_alphabet[0x80] = {
    '@',   0xa3,  '$',   0xa5,  0xe8,  0xe9,  0xf9,  0xec,
    0xf2,  0xc7,  '\n',  0xd8,  0xf8,  '\r',  0xc5,  0xe5,
    0x394, '_',   0x3a6, 0x393, 0x39b, 0x3a9, 0x3a0, 0x3a8,
    0x3a3, 0x398, 0x39e, 0xa0,  0xc6,  0xe6,  0xdf,  0xc9,
    ' ',   '!',   '\"',  '#',   0xa4,  '%',   '&',   '\'',
    '(',   ')',   '*',   '+',   ',',   '-',   '.',   '/',
    '0',   '1',   '2',   '3',   '4',   '5',   '6',   '7',
    '8',   '9',   ':',   ';',   '<',   '=',   '>',   '?',
    0xa1,  'A',   'B',   'C',   'D',   'E',   'F',   'G',
    'H',   'I',   'J',   'K',   'L',   'M',   'N',   'O',
    'P',   'Q',   'R',   'S',   'T',   'U',   'V',   'W',
    'X',   'Y',   'Z',   0xc4,  0xd6,  0xd1,  0xdc,  0xa7,
    0xbf,  'a',   'b',   'c',   'd',   'e',   'f',   'g',
    'h',   'i',   'j',   'k',   'l',   'm',   'n',   'o',
    'p',   'q',   'r',   's',   't',   'u',   'v',   'w',
    'x',   'y',   'z',   0xe4,  0xf6,  0xf1,  0xfc,  0xe0
};

static gunichar
GSM_to_UNICHAR(uint8_t c)
{
    if (c < G_N_ELEMENTS(gsm_default_alphabet))
        return gsm_default_alphabet[c];

    return UNREPL;
}

static gunichar
GSMext_to_UNICHAR(uint8_t c)
{
    switch (c)
    {
        case 0x0a: return 0x0c; /* form feed */
        case 0x14: return '^';
        case 0x28: return '{';
        case 0x29: return '}';
        case 0x2f: return '\\';
        case 0x3c: return '[';
        case 0x3d: return '~';
        case 0x3e: return ']';
        case 0x40: return '|';
        case 0x65: return 0x20ac; /* euro */
    }

    return UNREPL; /* invalid character */
}

#define GN_BYTE_MASK ((1 << bits) - 1)

#define GN_CHAR_ESCAPE 0x1b

static bool
char_is_escape(unsigned char value)
{
    return (value == GN_CHAR_ESCAPE);
}

static bool
handle_ts_23_038_char(wmem_strbuf_t *strbuf, uint8_t code_point,
                      bool saw_escape)
{
    gunichar       uchar;

    if (char_is_escape(code_point)) {
        /*
         * XXX - if saw_escape is true here, then this is
         * the case where we escape to "another extension table",
         * but TS 128 038 V11.0 doesn't specify such an extension
         * table.
         */
        saw_escape = true;
    } else {
        if (!(code_point & 0x80)) {
            /*
             * Code point is valid (7-bit).
             * Have we seen an escape?
             */
            if (saw_escape) {
                saw_escape = false;
                uchar = GSMext_to_UNICHAR(code_point);
            } else {
                uchar = GSM_to_UNICHAR(code_point);
            }
            wmem_strbuf_append_unichar(strbuf, uchar);
        } else {
            /* Invalid - put in a REPLACEMENT CHARACTER */
            wmem_strbuf_append_unichar(strbuf, UNREPL);
        }
    }
    return saw_escape;
}

uint8_t *
get_ts_23_038_7bits_string_packed(wmem_allocator_t *scope, const uint8_t *ptr,
                                  const int bit_offset, int no_of_chars)
{
    wmem_strbuf_t *strbuf;
    int            char_count;                  /* character counter for string */
    uint8_t        in_byte, out_byte, rest = 0x00;
    const uint8_t *start_ptr = ptr;
    bool           saw_escape = false;
    int            bits;

    strbuf = wmem_strbuf_new_sized(scope, no_of_chars+1);

    bits = bit_offset & 0x07;
    if (!bits) {
        bits = 7;
    }

    for(char_count = 0; char_count < no_of_chars; ptr++) {
        /* Get the next byte from the string. */
        in_byte = *ptr;

        /*
         * Combine the bits we've accumulated with bits from
         * that byte to make a 7-bit code point.
         */
        out_byte = ((in_byte & GN_BYTE_MASK) << (7 - bits)) | rest;

        /*
         * Leftover bits used in that code point.
         */
        rest = in_byte >> bits;

        /*
         * If we don't start from 0th bit, we shouldn't go to the
         * next char. Under *out_num we have now 0 and under Rest -
         * _first_ part of the char.
         */
        if ((start_ptr != ptr) || (bits == 7)) {
            saw_escape = handle_ts_23_038_char(strbuf, out_byte,
                saw_escape);
            char_count++;
        }

        /*
         * After reading 7 octets we have read 7 full characters
         * but we have 7 bits as well. This is the next character.
         */
        if ((bits == 1) && (char_count < no_of_chars)) {
            saw_escape = handle_ts_23_038_char(strbuf, rest,
                saw_escape);
            char_count++;
            bits = 7;
            rest = 0x00;
        } else {
            bits--;
        }
    }

    if (saw_escape) {
        /*
         * Escape not followed by anything.
         *
         * XXX - for now, show the escape as a REPLACEMENT
         * CHARACTER.
         */
        wmem_strbuf_append_unichar(strbuf, UNREPL);
    }

    return (uint8_t *)wmem_strbuf_finalize(strbuf);
}

uint8_t *
get_ts_23_038_7bits_string_unpacked(wmem_allocator_t *scope, const uint8_t *ptr,
                           int length)
{
    wmem_strbuf_t *strbuf;
    int            i;       /* Byte counter for string */
    bool           saw_escape = false;

    strbuf = wmem_strbuf_new_sized(scope, length+1);

    for (i = 0; i < length; i++)
        saw_escape = handle_ts_23_038_char(strbuf, *ptr++, saw_escape);

    return (uint8_t *)wmem_strbuf_finalize(strbuf);
}

/*
 * ETSI TS 102 221 Annex A.
 */
uint8_t *
get_etsi_ts_102_221_annex_a_string(wmem_allocator_t *scope, const uint8_t *ptr,
                                   int length)
{
    uint8_t        string_type;
    uint8_t        string_len;
    gunichar2      ucs2_base;
    wmem_strbuf_t *strbuf;
    unsigned       i;       /* Byte counter for string */
    bool           saw_escape = false;

    /*
     * get the first octet.
     */
    if (length == 0) {
        /* XXX - return error indication */
        strbuf = wmem_strbuf_new(scope, "");
        return (uint8_t *)wmem_strbuf_finalize(strbuf);
    }
    string_type = *ptr;
    ptr++;
    length--;

    if (string_type == 0x80) {
        /*
         * Annex A, coding scheme 1) - big-endian UCS-2.
         */
        return get_ucs_2_string(scope, ptr, length, ENC_BIG_ENDIAN);
    }

    /*
     * Annex A, coding schemes 2) and 3):
     *
     *    the second byte is the number of characters (characters,
     *    not octets) in the string;
     *
     *    for coding scheme 2), the third byte defines bits 15 to 8
     *    of all UCS-2 characters in the string (all bit numbers are
     *    1-origin, so bit 1 is the low-order bit), with bit 16 being 0;
     *
     *    for coding scheme 3), the third byte and fourth bytes, treated
     *    as a big-endian value, define the base value for all UCS-2
     *    characters in the string;
     *
     *    for all subsequent bytes, if bit 8 is 0, it's a character
     *    in the GSM Default Alphabet, otherwise, it is added to
     *    the UCS-2 base value to give a UCS-2 character.
     *
     * XXX - that doesn't seem to indicate that a byte of 0x1b is
     * treated as an escape character, it just says that a single octet
     * with the 8th bit not set is a GSM Default Alphabet character.
     */

    /*
     * Get the string length, in characters.
     */
    if (length == 0) {
        /* XXX - return error indication */
        strbuf = wmem_strbuf_new(scope, "");
        return (uint8_t *)wmem_strbuf_finalize(strbuf);
    }
    string_len = *ptr;
    ptr++;
    length--;

    strbuf = wmem_strbuf_new_sized(scope, 2*string_len+1);

    /*
     * Get the UCS-2 base.
     */
    if (string_type == 0x81) {
        if (length == 0) {
            /* XXX - return error indication */
            return (uint8_t *)wmem_strbuf_finalize(strbuf);
	}
        ucs2_base = (*ptr) << 7;
        ptr++;
        length--;
    } else if (string_type == 0x82) {
        if (length == 0) {
            /* XXX - return error indication */
            return (uint8_t *)wmem_strbuf_finalize(strbuf);
	}
        ucs2_base = (*ptr) << 8;
        ptr++;
        length--;

        if (length == 0) {
            /* XXX - return error indication */
            return (uint8_t *)wmem_strbuf_finalize(strbuf);
	}
        ucs2_base |= *ptr;
        ptr++;
        length--;
    } else {
        /* Invalid string type. */
        /* XXX - return error indication */
        return (uint8_t *)wmem_strbuf_finalize(strbuf);
    }

    for (i = 0; i < string_len; i++) {
        uint8_t byte;

        if (length == 0) {
            /* XXX - return error indication */
            return (uint8_t *)wmem_strbuf_finalize(strbuf);
	}
        byte = *ptr;
        if ((byte & 0x80) == 0) {
            saw_escape = handle_ts_23_038_char(strbuf, byte, saw_escape);
        } else {
            gunichar2 uchar;

            /*
             * XXX - if saw_escape is true, this is bogus.
             *
             * XXX - if there are an odd number of bytes, should put a
             * REPLACEMENT CHARACTER at the end.
             */
            uchar = ucs2_base + (byte & 0x7f);
            wmem_strbuf_append_unichar_validated(strbuf, uchar);
        }
    }

    return (uint8_t *)wmem_strbuf_finalize(strbuf);
}

uint8_t *
get_ascii_7bits_string(wmem_allocator_t *scope, const uint8_t *ptr,
                       const int bit_offset, int no_of_chars)
{
    wmem_strbuf_t *strbuf;
    int            char_count;                  /* character counter for string */
    uint8_t        in_byte, out_byte, rest = 0x00;
    const uint8_t *start_ptr = ptr;
    int            bits;

    bits = bit_offset & 0x07;
    if (!bits) {
        bits = 7;
    }

    strbuf = wmem_strbuf_new_sized(scope, no_of_chars+1);
    for(char_count = 0; char_count < no_of_chars; ptr++) {
        /* Get the next byte from the string. */
        in_byte = *ptr;

        /*
         * Combine the bits we've accumulated with bits from
         * that byte to make a 7-bit code point.
         */
        out_byte = (in_byte >> (8 - bits)) | rest;

        /*
         * Leftover bits used in that code point.
         */
        rest = (in_byte << (bits - 1)) & 0x7f;

        /*
         * If we don't start from 0th bit, we shouldn't go to the
         * next char. Under *out_num we have now 0 and under Rest -
         * _first_ part of the char.
         */
        if ((start_ptr != ptr) || (bits == 7)) {
            wmem_strbuf_append_c(strbuf, out_byte);
            char_count++;
        }

        /*
         * After reading 7 octets we have read 7 full characters
         * but we have 7 bits as well. This is the next character.
         */
        if ((bits == 1) && (char_count < no_of_chars)) {
            wmem_strbuf_append_c(strbuf, rest);
            char_count++;
            bits = 7;
            rest = 0x00;
        } else {
            bits--;
        }
    }

    return (uint8_t *)wmem_strbuf_finalize(strbuf);
}

/* Tables for EBCDIC code pages */

/* EBCDIC common; based on the table in appendix H of ESA/370 Principles
   of Operation, but with some code points that don't correspond to
   the same characters in code pages 037 and 1158 mapped to REPLACEMENT
   CHARACTER - there may be more code points of that sort */

/* There are a few EBCDIC control codes that, strictly speaking, do not
 * map to any control codes in ASCII or Unicode for that matter. The
 * customary treatment is to map them in a particular way to ASCII C1
 * control codes that have no exact equivalent in EBCDIC, as below. */
const gunichar2 charset_table_ebcdic[256] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x009c, 0x0009, 0x0086, 0x007f,
    0x0097, 0x008d, 0x008e, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
    0x0010, 0x0011, 0x0012, 0x0013, 0x009d, 0x0085, 0x0008, 0x0087,
    0x0018, 0x0019, 0x0092, 0x008f, 0x001c, 0x001d, 0x001e, 0x001f,
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x000a, 0x0017, 0x001b,
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x0005, 0x0006, 0x0007,
    UNREPL, UNREPL, 0x0016, 0x0093, 0x0094, 0x0095, 0x0096, 0x0004,
    0x0098, 0x0099, 0x009a, 0x009b, 0x0014, 0x0015, UNREPL, 0x001a,
    0x0020, 0x00a0, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, UNREPL, UNREPL, 0x002e, 0x003c, 0x0028, 0x002b, UNREPL,
    0x0026, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, UNREPL, UNREPL, 0x0024, 0x002a, 0x0029, 0x003b, UNREPL,
    0x002d, 0x002f, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, UNREPL, UNREPL, 0x002c, 0x0025, 0x005f, 0x003e, 0x003f,
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, 0x0060, 0x003a, 0x0023, 0x0040, 0x0027, 0x003d, 0x0022,
    UNREPL, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f, 0x0070,
    0x0071, 0x0072, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, 0x007e, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078,
    0x0079, 0x007a, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    0x007b, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    0x007d, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f, 0x0050,
    0x0051, 0x0052, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    0x005c, UNREPL, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058,
    0x0059, 0x005a, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL, UNREPL,
};

/* EBCDIC code page 037 */
const gunichar2 charset_table_ebcdic_cp037[256] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x009c, 0x0009, 0x0086, 0x007f,
    0x0097, 0x008d, 0x008e, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
    0x0010, 0x0011, 0x0012, 0x0013, 0x009d, 0x0085, 0x0008, 0x0087,
    0x0018, 0x0019, 0x0092, 0x008f, 0x001c, 0x001d, 0x001e, 0x001f,
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x000a, 0x0017, 0x001b,
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x0005, 0x0006, 0x0007,
    0x0090, 0x0091, 0x0016, 0x0093, 0x0094, 0x0095, 0x0096, 0x0004,
    0x0098, 0x0099, 0x009a, 0x009b, 0x0014, 0x0015, 0x009e, 0x001a,
    0x0020, 0x00a0, 0x00e2, 0x00e4, 0x00e0, 0x00e1, 0x00e3, 0x00e5,
    0x00e7, 0x00f1, 0x00a2, 0x002e, 0x003c, 0x0028, 0x002b, 0x007c,
    0x0026, 0x00e9, 0x00ea, 0x00eb, 0x00e8, 0x00ed, 0x00ee, 0x00ef,
    0x00ec, 0x00df, 0x0021, 0x0024, 0x002a, 0x0029, 0x003b, 0x00ac,
    0x002d, 0x002f, 0x00c2, 0x00c4, 0x00c0, 0x00c1, 0x00c3, 0x00c5,
    0x00c7, 0x00d1, 0x00a6, 0x002c, 0x0025, 0x005f, 0x003e, 0x003f,
    0x00f8, 0x00c9, 0x00ca, 0x00cb, 0x00c8, 0x00cd, 0x00ce, 0x00cf,
    0x00cc, 0x0060, 0x003a, 0x0023, 0x0040, 0x0027, 0x003d, 0x0022,
    0x00d8, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x00ab, 0x00bb, 0x00f0, 0x00fd, 0x00fe, 0x00b1,
    0x00b0, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f, 0x0070,
    0x0071, 0x0072, 0x00aa, 0x00ba, 0x00e6, 0x00b8, 0x00c6, 0x00a4,
    0x00b5, 0x007e, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078,
    0x0079, 0x007a, 0x00a1, 0x00bf, 0x00d0, 0x00dd, 0x00de, 0x00ae,
    0x005e, 0x00a3, 0x00a5, 0x00b7, 0x00a9, 0x00a7, 0x00b6, 0x00bc,
    0x00bd, 0x00be, 0x005b, 0x005d, 0x00af, 0x00a8, 0x00b4, 0x00d7,
    0x007b, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x00ad, 0x00f4, 0x00f6, 0x00f2, 0x00f3, 0x00f5,
    0x007d, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f, 0x0050,
    0x0051, 0x0052, 0x00b9, 0x00fb, 0x00fc, 0x00f9, 0x00fa, 0x00ff,
    0x005c, 0x00f7, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058,
    0x0059, 0x005a, 0x00b2, 0x00d4, 0x00d6, 0x00d2, 0x00d3, 0x00d5,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x00b3, 0x00db, 0x00dc, 0x00d9, 0x00da, 0x009f,
};

/* EBCDIC code page 500
 * https://www.ibm.com/support/pages/conversion-character-differences-between-ccsid-037-and-ccsid-500
 * CCSID 500 ("International Latin-1") has exactly the same repertoire as 37,
 * covering all of ISO-8559-1, but with seven code points permuted.
 * It is notable because it is the default code page for DRDA:
 * https://www.ibm.com/support/pages/drda-user-id-and-password-not-being-transmitted-correctly-when-containing-characters-%C2%AC-%C2%A2?lnk=hm
 */
const gunichar2 charset_table_ebcdic_cp500[256] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x009c, 0x0009, 0x0086, 0x007f,
    0x0097, 0x008d, 0x008e, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
    0x0010, 0x0011, 0x0012, 0x0013, 0x009d, 0x0085, 0x0008, 0x0087,
    0x0018, 0x0019, 0x0092, 0x008f, 0x001c, 0x001d, 0x001e, 0x001f,
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x000a, 0x0017, 0x001b,
    0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x0005, 0x0006, 0x0007,
    0x0090, 0x0091, 0x0016, 0x0093, 0x0094, 0x0095, 0x0096, 0x0004,
    0x0098, 0x0099, 0x009a, 0x009b, 0x0014, 0x0015, 0x009e, 0x001a,
    0x0020, 0x00a0, 0x00e2, 0x00e4, 0x00e0, 0x00e1, 0x00e3, 0x00e5,
    0x00e7, 0x00f1, 0x005b, 0x002e, 0x003c, 0x0028, 0x002b, 0x0021,
    0x0026, 0x00e9, 0x00ea, 0x00eb, 0x00e8, 0x00ed, 0x00ee, 0x00ef,
    0x00ec, 0x00df, 0x005d, 0x0024, 0x002a, 0x0029, 0x003b, 0x005e,
    0x002d, 0x002f, 0x00c2, 0x00c4, 0x00c0, 0x00c1, 0x00c3, 0x00c5,
    0x00c7, 0x00d1, 0x00a6, 0x002c, 0x0025, 0x005f, 0x003e, 0x003f,
    0x00f8, 0x00c9, 0x00ca, 0x00cb, 0x00c8, 0x00cd, 0x00ce, 0x00cf,
    0x00cc, 0x0060, 0x003a, 0x0023, 0x0040, 0x0027, 0x003d, 0x0022,
    0x00d8, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
    0x0068, 0x0069, 0x00ab, 0x00bb, 0x00f0, 0x00fd, 0x00fe, 0x00b1,
    0x00b0, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f, 0x0070,
    0x0071, 0x0072, 0x00aa, 0x00ba, 0x00e6, 0x00b8, 0x00c6, 0x00a4,
    0x00b5, 0x007e, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078,
    0x0079, 0x007a, 0x00a1, 0x00bf, 0x00d0, 0x00dd, 0x00de, 0x00ae,
    0x00a2, 0x00a3, 0x00a5, 0x00b7, 0x00a9, 0x00a7, 0x00b6, 0x00bc,
    0x00bd, 0x00be, 0x00ac, 0x007c, 0x00af, 0x00a8, 0x00b4, 0x00d7,
    0x007b, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x00ad, 0x00f4, 0x00f6, 0x00f2, 0x00f3, 0x00f5,
    0x007d, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f, 0x0050,
    0x0051, 0x0052, 0x00b9, 0x00fb, 0x00fc, 0x00f9, 0x00fa, 0x00ff,
    0x005c, 0x00f7, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058,
    0x0059, 0x005a, 0x00b2, 0x00d4, 0x00d6, 0x00d2, 0x00d3, 0x00d5,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
    0x0038, 0x0039, 0x00b3, 0x00db, 0x00dc, 0x00d9, 0x00da, 0x009f,
};

/*
 * Given a wmem scope, a pointer, a length, and a translation table with
 * 256 entries, treat the string of bytes referred to by the pointer and
 * length as a string encoded using one octet per character, with octets
 * being mapped by the translation table to 2-byte Unicode Basic Multilingual
 * Plane characters (including REPLACEMENT CHARACTER), and return a
 * pointer to a UTF-8 string, allocated using the wmem scope.
 */
uint8_t *
get_nonascii_unichar2_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, const gunichar2 table[256])
{
    wmem_strbuf_t *str;

    str = wmem_strbuf_new_sized(scope, length+1);

    while (length > 0) {
        uint8_t ch = *ptr;

        wmem_strbuf_append_unichar(str, table[ch]);
        ptr++;
        length--;
    }

    return (uint8_t *) wmem_strbuf_finalize(str);
}

/*
 * Given a wmem scope, a pointer, a length, and a string referring to an
 * encoding (recognized by iconv), treat the bytes referred to by the pointer
 * and length as a string in that encoding, and return a pointer to a UTF-8
 * string, allocated using the wmem scope, converted from the original
 * encoding having substituted REPLACEMENT CHARACTER according to the
 * Unicode Standard 5.22 U+FFFD Substitution for Conversion
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 */
static uint8_t *
get_string_enc_iconv(wmem_allocator_t *scope, const uint8_t *ptr, int length, const char *encoding)
{
    GIConv cd;
    size_t inbytes, outbytes;
    size_t tempstr_size, bytes_written;
    size_t err;
    size_t max_subpart, tempinbytes;
    char *outptr, *tempstr;

    wmem_strbuf_t *str;

    if ((cd = g_iconv_open("UTF-8", encoding)) == (GIConv) -1) {
        REPORT_DISSECTOR_BUG("Unable to allocate iconv() converter from %s to UTF-8", encoding);
        /* Most likely to be a programming error passing in a bad encoding
         * name. However, could be a issue with the iconv support on the
         * system running WS. GLib requires iconv/libiconv, but is it possible
         * that some versions don't support all common encodings? */
    }

    inbytes = length;
    str = wmem_strbuf_new_sized(scope, length+1);
    /* XXX: If speed becomes an issue, the faster way to do this would
     * involve passing the wmem_strbuf_t's string buffer directly into
     * g_iconv to avoid a memcpy later, but that requires changes to the
     * wmem_strbuf interface to have non const access to the string buffer,
     * and to manipulate the used length directly. */
    outbytes = tempstr_size = MAX(8, length);
    outptr = tempstr = (char *)g_malloc(outbytes);
    while (inbytes > 0) {
        err = g_iconv(cd, (char **)&ptr, &inbytes, &outptr, &outbytes);
        bytes_written = outptr - tempstr;
        wmem_strbuf_append_len(str, tempstr, bytes_written);
        outptr = tempstr;
        outbytes = tempstr_size;

        if (err == (size_t) -1) {
            /* Errors */
            switch (errno) {
                case EINVAL:
                    /* Incomplete sequence at the end, not an error */
                    wmem_strbuf_append_unichar_repl(str);
                    inbytes = 0;
                    break;
                case E2BIG:
                    /* Not enough room (UTF-8 longer than the initial buffer),
                     * start back at the beginning of the buffer */
                    break;
                case EILSEQ:
                    /* Find the maximal subpart of the ill-formed sequence */
                    errno = EINVAL;
                    for (max_subpart = 1; err == (size_t)-1 && errno == EINVAL; max_subpart++) {
                        tempinbytes = max_subpart;
                        err = g_iconv(cd, (char **)&ptr, &tempinbytes,
                                &outptr, &outbytes);
                    }
                    max_subpart = MAX(1, max_subpart-1);
                    ptr += max_subpart;
                    inbytes -= max_subpart;
                    wmem_strbuf_append_unichar_repl(str);
                    outptr = tempstr;
                    outbytes = tempstr_size;
                    break;
                default:
                    /* Unexpected conversion error, unrecoverable */
                    g_free(tempstr);
                    g_iconv_close(cd);
                    REPORT_DISSECTOR_BUG("Unexpected iconv() error when converting from %s to UTF-8", encoding);
                    break;
            }
        } else {
            /* Otherwise err is the number of replacement characters used,
             * but we don't care about that. */
            /* If we were converting to ISO-2022-JP or some other stateful
             * decoder with shift sequences (e.g. EBCDIC mixed-byte), a
             * final call with NULL input in order to output the shift
             * sequence back to initial state might make sense, but not
             * needed for UTF-8. */
        }
    }

    g_free(tempstr);
    g_iconv_close(cd);
    return (uint8_t *) wmem_strbuf_finalize(str);
}

/*
 * Given a wmem scope, a pointer, and a length, treat the bytes referred to
 * by the pointer and length as a GB18030 encoded string, and return a pointer
 * to a UTF-8 string, allocated using the wmem scope, converted having
 * substituted REPLACEMENT CHARACTER according to the Unicode Standard
 * 5.22 U+FFFD Substitution for Conversion.
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 *
 * As expected, this will also decode GBK and GB2312 strings.
 */
uint8_t *
get_gb18030_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    /* iconv/libiconv support is guaranteed with GLib. Support this
     * via iconv, at least for now. */
    /* GNU libiconv has supported GB18030 (~ Windows Code page 54936) since
     * 2000-10-24 and version 1.4, is there is a system that compiles current
     * Wireshark yet its iconv only supports GBK (~ Windows Code page 936)? */
    const char *encoding = "GB18030";
    GIConv cd;
    if ((cd = g_iconv_open("UTF-8", encoding)) == (GIConv) -1) {
        encoding = "GBK";
        /* GB18030 is backwards compatible, at worst this will mean a few
         * extra REPLACEMENT CHARACTERs - GBK lacks the four byte encodings
         * from GB18030, which are all pairs of two byte sequences
         * 0x[81-FE] 0x[30-39]; that trailing byte is illegal in GBK
         * and thus the 4 byte characters will be replaced with two
         * REPLACEMENT CHARACTERs. */
    } else {
        g_iconv_close(cd);
    }
    return get_string_enc_iconv(scope, ptr, length, encoding);
}

/*
 * Given a wmem scope, a pointer, and a length, treat the bytes referred to
 * by the pointer and length as a EUC-KR encoded string, and return a pointer
 * to a UTF-8 string, allocated using the wmem scope, converted having
 * substituted REPLACEMENT CHARACTER according to the Unicode Standard
 * 5.22 U+FFFD Substitution for Conversion.
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 */
uint8_t *
get_euc_kr_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    /* iconv/libiconv support is guaranteed with GLib. Support this
     * via iconv, at least for now. */
    return get_string_enc_iconv(scope, ptr, length, "EUC-KR");
}

/* T.61 to UTF-8 conversion table from OpenLDAP project
 * https://www.openldap.org/devel/gitweb.cgi?p=openldap.git;a=blob;f=libraries/libldap/t61.c;hb=HEAD
 */
static const gunichar2 t61_tab[] = {
    0x000, 0x001, 0x002, 0x003, 0x004, 0x005, 0x006, 0x007,
    0x008, 0x009, 0x00a, 0x00b, 0x00c, 0x00d, 0x00e, 0x00f,
    0x010, 0x011, 0x012, 0x013, 0x014, 0x015, 0x016, 0x017,
    0x018, 0x019, 0x01a, 0x01b, 0x01c, 0x01d, 0x01e, 0x01f,
    0x020, 0x021, 0x022, 0x000, 0x000, 0x025, 0x026, 0x027,
    0x028, 0x029, 0x02a, 0x02b, 0x02c, 0x02d, 0x02e, 0x02f,
    0x030, 0x031, 0x032, 0x033, 0x034, 0x035, 0x036, 0x037,
    0x038, 0x039, 0x03a, 0x03b, 0x03c, 0x03d, 0x03e, 0x03f,
    0x040, 0x041, 0x042, 0x043, 0x044, 0x045, 0x046, 0x047,
    0x048, 0x049, 0x04a, 0x04b, 0x04c, 0x04d, 0x04e, 0x04f,
    0x050, 0x051, 0x052, 0x053, 0x054, 0x055, 0x056, 0x057,
    0x058, 0x059, 0x05a, 0x05b, 0x000, 0x05d, 0x000, 0x05f,
    0x000, 0x061, 0x062, 0x063, 0x064, 0x065, 0x066, 0x067,
    0x068, 0x069, 0x06a, 0x06b, 0x06c, 0x06d, 0x06e, 0x06f,
    0x070, 0x071, 0x072, 0x073, 0x074, 0x075, 0x076, 0x077,
    0x078, 0x079, 0x07a, 0x000, 0x07c, 0x000, 0x000, 0x07f,
    0x080, 0x081, 0x082, 0x083, 0x084, 0x085, 0x086, 0x087,
    0x088, 0x089, 0x08a, 0x08b, 0x08c, 0x08d, 0x08e, 0x08f,
    0x090, 0x091, 0x092, 0x093, 0x094, 0x095, 0x096, 0x097,
    0x098, 0x099, 0x09a, 0x09b, 0x09c, 0x09d, 0x09e, 0x09f,
    0x0a0, 0x0a1, 0x0a2, 0x0a3, 0x024, 0x0a5, 0x023, 0x0a7,
    0x0a4, 0x000, 0x000, 0x0ab, 0x000, 0x000, 0x000, 0x000,
    0x0b0, 0x0b1, 0x0b2, 0x0b3, 0x0d7, 0x0b5, 0x0b6, 0x0b7,
    0x0f7, 0x000, 0x000, 0x0bb, 0x0bc, 0x0bd, 0x0be, 0x0bf,
    0x000, 0x300, 0x301, 0x302, 0x303, 0x304, 0x306, 0x307,
    0x308, 0x000, 0x30a, 0x327, 0x332, 0x30b, 0x328, 0x30c,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
    0x2126, 0xc6, 0x0d0, 0x0aa, 0x126, 0x000, 0x132, 0x13f,
    0x141, 0x0d8, 0x152, 0x0ba, 0x0de, 0x166, 0x14a, 0x149,
    0x138, 0x0e6, 0x111, 0x0f0, 0x127, 0x131, 0x133, 0x140,
    0x142, 0x0f8, 0x153, 0x0df, 0x0fe, 0x167, 0x14b, 0x000
};

typedef gunichar2 wvec16[16];
typedef gunichar2 wvec32[32];

/* Substitutions when 0xc1-0xcf appears by itself or with space 0x20 */
static const wvec16 accents = {
    0x000, 0x060, 0x0b4, 0x05e, 0x07e, 0x0af, 0x2d8, 0x2d9,
    0x0a8, 0x000, 0x2da, 0x0b8, 0x000, 0x2dd, 0x2db, 0x2c7};

/* In the following tables, base characters commented in (parentheses)
 * are not defined by T.61 but are mapped anyway since their Unicode
 * composite exists.
 */

/* Grave accented chars AEIOU (NWY) */
static const wvec32 c1_vec1 = {
    /* Upper case */
    0, 0xc0, 0, 0, 0, 0xc8, 0, 0, 0, 0xcc, 0, 0, 0, 0, 0x1f8, 0xd2,
    0, 0, 0, 0, 0, 0xd9, 0, 0x1e80, 0, 0x1ef2, 0, 0, 0, 0, 0, 0};
static const wvec32 c1_vec2 = {
    /* Lower case */
    0, 0xe0, 0, 0, 0, 0xe8, 0, 0, 0, 0xec, 0, 0, 0, 0, 0x1f9, 0xf2,
    0, 0, 0, 0, 0, 0xf9, 0, 0x1e81, 0, 0x1ef3, 0, 0, 0, 0, 0, 0};

static const wvec32 *c1_grave[] = {
    NULL, NULL, &c1_vec1, &c1_vec2, NULL, NULL, NULL, NULL
};

/* Acute accented chars AEIOUYCLNRSZ (GKMPW) */
static const wvec32 c2_vec1 = {
    /* Upper case */
    0, 0xc1, 0, 0x106, 0, 0xc9, 0, 0x1f4,
    0, 0xcd, 0, 0x1e30, 0x139, 0x1e3e, 0x143, 0xd3,
    0x1e54, 0, 0x154, 0x15a, 0, 0xda, 0, 0x1e82,
    0, 0xdd, 0x179, 0, 0, 0, 0, 0};
static const wvec32 c2_vec2 = {
    /* Lower case */
    0, 0xe1, 0, 0x107, 0, 0xe9, 0, 0x1f5,
    0, 0xed, 0, 0x1e31, 0x13a, 0x1e3f, 0x144, 0xf3,
    0x1e55, 0, 0x155, 0x15b, 0, 0xfa, 0, 0x1e83,
    0, 0xfd, 0x17a, 0, 0, 0, 0, 0};
static const wvec32 c2_vec3 = {
    /* (AE and ae) */
    0, 0x1fc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0x1fd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static const wvec32 *c2_acute[] = {
    NULL, NULL, &c2_vec1, &c2_vec2, NULL, NULL, NULL, &c2_vec3
};

/* Circumflex AEIOUYCGHJSW (Z) */
static const wvec32 c3_vec1 = {
    /* Upper case */
    0, 0xc2, 0, 0x108, 0, 0xca, 0, 0x11c,
    0x124, 0xce, 0x134, 0, 0, 0, 0, 0xd4,
    0, 0, 0, 0x15c, 0, 0xdb, 0, 0x174,
    0, 0x176, 0x1e90, 0, 0, 0, 0, 0};
static const wvec32 c3_vec2 = {
    /* Lower case */
    0, 0xe2, 0, 0x109, 0, 0xea, 0, 0x11d,
    0x125, 0xee, 0x135, 0, 0, 0, 0, 0xf4,
    0, 0, 0, 0x15d, 0, 0xfb, 0, 0x175,
    0, 0x177, 0x1e91, 0, 0, 0, 0, 0};
static const wvec32 *c3_circumflex[] = {
    NULL, NULL, &c3_vec1, &c3_vec2, NULL, NULL, NULL, NULL
};

/* Tilde AIOUN (EVY) */
static const wvec32 c4_vec1 = {
    /* Upper case */
    0, 0xc3, 0, 0, 0, 0x1ebc, 0, 0, 0, 0x128, 0, 0, 0, 0, 0xd1, 0xd5,
    0, 0, 0, 0, 0, 0x168, 0x1e7c, 0, 0, 0x1ef8, 0, 0, 0, 0, 0, 0};
static const wvec32 c4_vec2 = {
    /* Lower case */
    0, 0xe3, 0, 0, 0, 0x1ebd, 0, 0, 0, 0x129, 0, 0, 0, 0, 0xf1, 0xf5,
    0, 0, 0, 0, 0, 0x169, 0x1e7d, 0, 0, 0x1ef9, 0, 0, 0, 0, 0, 0};
static const wvec32 *c4_tilde[] = {
    NULL, NULL, &c4_vec1, &c4_vec2, NULL, NULL, NULL, NULL
};

/* Macron AEIOU (YG) */
static const wvec32 c5_vec1 = {
    /* Upper case */
    0, 0x100, 0, 0, 0, 0x112, 0, 0x1e20, 0, 0x12a, 0, 0, 0, 0, 0, 0x14c,
    0, 0, 0, 0, 0, 0x16a, 0, 0, 0, 0x232, 0, 0, 0, 0, 0, 0};
static const wvec32 c5_vec2 = {
    /* Lower case */
    0, 0x101, 0, 0, 0, 0x113, 0, 0x1e21, 0, 0x12b, 0, 0, 0, 0, 0, 0x14d,
    0, 0, 0, 0, 0, 0x16b, 0, 0, 0, 0x233, 0, 0, 0, 0, 0, 0};
static const wvec32 c5_vec3 = {
    /* (AE and ae) */
    0, 0x1e2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0x1e3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *c5_macron[] = {
    NULL, NULL, &c5_vec1, &c5_vec2, NULL, NULL, NULL, &c5_vec3
};

/* Breve AUG (EIO) */
static const wvec32 c6_vec1 = {
    /* Upper case */
    0, 0x102, 0, 0, 0, 0x114, 0, 0x11e, 0, 0x12c, 0, 0, 0, 0, 0, 0x14e,
    0, 0, 0, 0, 0, 0x16c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 c6_vec2 = {
    /* Lower case */
    0, 0x103, 0, 0, 0, 0x115, 0, 0x11f, 0, 0x12d, 0, 0, 0, 0, 0, 0x14f,
    0, 0, 0, 0, 0, 0x16d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *c6_breve[] = {
    NULL, NULL, &c6_vec1, &c6_vec2, NULL, NULL, NULL, NULL
};

/* Dot Above CEGIZ (AOBDFHMNPRSTWXY) */
static const wvec32 c7_vec1 = {
    /* Upper case */
    0, 0x226, 0x1e02, 0x10a, 0x1e0a, 0x116, 0x1e1e, 0x120,
    0x1e22, 0x130, 0, 0, 0, 0x1e40, 0x1e44, 0x22e,
    0x1e56, 0, 0x1e58, 0x1e60, 0x1e6a, 0, 0, 0x1e86,
    0x1e8a, 0x1e8e, 0x17b, 0, 0, 0, 0, 0};
static const wvec32 c7_vec2 = {
    /* Lower case */
    0, 0x227, 0x1e03, 0x10b, 0x1e0b, 0x117, 0x1e1f, 0x121,
    0x1e23, 0, 0, 0, 0, 0x1e41, 0x1e45, 0x22f,
    0x1e57, 0, 0x1e59, 0x1e61, 0x1e6b, 0, 0, 0x1e87,
    0x1e8b, 0x1e8f, 0x17c, 0, 0, 0, 0, 0};
static const wvec32 *c7_dotabove[] = {
    NULL, NULL, &c7_vec1, &c7_vec2, NULL, NULL, NULL, NULL
};

/* Diaeresis AEIOUY (HWXt) */
static const wvec32 c8_vec1 = {
    /* Upper case */
    0, 0xc4, 0, 0, 0, 0xcb, 0, 0, 0x1e26, 0xcf, 0, 0, 0, 0, 0, 0xd6,
    0, 0, 0, 0, 0, 0xdc, 0, 0x1e84, 0x1e8c, 0x178, 0, 0, 0, 0, 0, 0};
static const wvec32 c8_vec2 = {
    /* Lower case */
    0, 0xe4, 0, 0, 0, 0xeb, 0, 0, 0x1e27, 0xef, 0, 0, 0, 0, 0, 0xf6,
    0, 0, 0, 0, 0x1e97, 0xfc, 0, 0x1e85, 0x1e8d, 0xff, 0, 0, 0, 0, 0, 0};
static const wvec32 *c8_diaeresis[] = {
    NULL, NULL, &c8_vec1, &c8_vec2, NULL, NULL, NULL, NULL
};

/* Ring Above AU (wy) */
static const wvec32 ca_vec1 = {
    /* Upper case */
    0, 0xc5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0x16e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 ca_vec2 = {
    /* Lower case */
    0, 0xe5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0x16f, 0, 0x1e98, 0, 0x1e99, 0, 0, 0, 0, 0, 0};
static const wvec32 *ca_ringabove[] = {
    NULL, NULL, &ca_vec1, &ca_vec2, NULL, NULL, NULL, NULL
};

/* Cedilla CGKLNRST (EDH) */
static const wvec32 cb_vec1 = {
    /* Upper case */
    0, 0, 0, 0xc7, 0x1e10, 0x228, 0, 0x122,
    0x1e28, 0, 0, 0x136, 0x13b, 0, 0x145, 0,
    0, 0, 0x156, 0x15e, 0x162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 cb_vec2 = {
    /* Lower case */
    0, 0, 0, 0xe7, 0x1e11, 0x229, 0, 0x123,
    0x1e29, 0, 0, 0x137, 0x13c, 0, 0x146, 0,
    0, 0, 0x157, 0x15f, 0x163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *cb_cedilla[] = {
    NULL, NULL, &cb_vec1, &cb_vec2, NULL, NULL, NULL, NULL
};

/* Double Acute Accent OU */
static const wvec32 cd_vec1 = {
    /* Upper case */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x150,
    0, 0, 0, 0, 0, 0x170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 cd_vec2 = {
    /* Lower case */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x151,
    0, 0, 0, 0, 0, 0x171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *cd_doubleacute[] = {
    NULL, NULL, &cd_vec1, &cd_vec2, NULL, NULL, NULL, NULL
};

/* Ogonek AEIU (O) */
static const wvec32 ce_vec1 = {
    /* Upper case */
    0, 0x104, 0, 0, 0, 0x118, 0, 0, 0, 0x12e, 0, 0, 0, 0, 0, 0x1ea,
    0, 0, 0, 0, 0, 0x172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 ce_vec2 = {
    /* Lower case */
    0, 0x105, 0, 0, 0, 0x119, 0, 0, 0, 0x12f, 0, 0, 0, 0, 0, 0x1eb,
    0, 0, 0, 0, 0, 0x173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *ce_ogonek[] = {
    NULL, NULL, &ce_vec1, &ce_vec2, NULL, NULL, NULL, NULL
};

/* Caron CDELNRSTZ (AIOUGKjH) */
static const wvec32 cf_vec1 = {
    /* Upper case */
    0, 0x1cd, 0, 0x10c, 0x10e, 0x11a, 0, 0x1e6,
    0x21e, 0x1cf, 0, 0x1e8, 0x13d, 0, 0x147, 0x1d1,
    0, 0, 0x158, 0x160, 0x164, 0x1d3, 0, 0,
    0, 0, 0x17d, 0, 0, 0, 0, 0};
static const wvec32 cf_vec2 = {
    /* Lower case */
    0, 0x1ce, 0, 0x10d, 0x10f, 0x11b, 0, 0x1e7,
    0x21f, 0x1d0, 0x1f0, 0x1e9, 0x13e, 0, 0x148, 0x1d2,
    0, 0, 0x159, 0x161, 0x165, 0x1d4, 0, 0,
    0, 0, 0x17e, 0, 0, 0, 0, 0};
static const wvec32 *cf_caron[] = {
    NULL, NULL, &cf_vec1, &cf_vec2, NULL, NULL, NULL, NULL
};

static const wvec32 **cx_tab[] = {
    NULL, c1_grave, c2_acute, c3_circumflex, c4_tilde, c5_macron,
    c6_breve, c7_dotabove, c8_diaeresis, NULL, ca_ringabove,
    cb_cedilla, NULL, cd_doubleacute, ce_ogonek, cf_caron };

uint8_t *
get_t61_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    int            i;
    const uint8_t *c;
    wmem_strbuf_t *strbuf;

    strbuf = wmem_strbuf_new_sized(scope, length+1);

    for (i = 0, c = ptr; i < length; c++, i++) {
        if (!t61_tab[*c]) {
            wmem_strbuf_append_unichar(strbuf, UNREPL);
        } else if (i < length - 1 && (*c & 0xf0) == 0xc0) {
            int j = *c & 0x0f;
            /* If this is the end of the string, or if the base
             * character is just a space, treat this as a regular
             * spacing character.
             */
            if ((!c[1] || c[1] == 0x20) && accents[j]) {
                wmem_strbuf_append_unichar(strbuf, accents[j]);
            } else if (cx_tab[j] && cx_tab[j][c[1]>>5] &&
                /* We have a composite mapping for this pair */
                       (*cx_tab[j][c[1]>>5])[c[1]&0x1f]) {
                wmem_strbuf_append_unichar(strbuf, (*cx_tab[j][c[1]>>5])[c[1]&0x1f]);
            } else {
                /* No mapping, just swap it around so the base
                 * character comes first.
                 */
                wmem_strbuf_append_unichar(strbuf, c[1]);
                wmem_strbuf_append_unichar(strbuf, t61_tab[*c]);
            }
            c++; i++;
            continue;
        } else {
            wmem_strbuf_append_unichar(strbuf, t61_tab[*c]);
        }
    }

    return (uint8_t *)wmem_strbuf_finalize(strbuf);
}

/* The DECT standard charset from ETSI EN 300 175-5 Annex D
 */
static const gunichar2 dect_standard_8bits_code_table[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ' ',  '!',  '\"', '#',  '$',  '%',  '&',  '\'',
    '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
    '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
    '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
    '@',  'A',  'B',  'C',  'D',  'E',  'F',  'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  '[', '\\',  ']',  '^',  '_',
    '`',  'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  '{',  '|',  '}',  '~', 0x7f,
};

uint8_t *
get_dect_standard_8bits_string(wmem_allocator_t *scope, const uint8_t *ptr, int length)
{
    int            position;
    const uint8_t *current_byte_ptr;
    wmem_strbuf_t *strbuf;

    strbuf = wmem_strbuf_new_sized(scope, length+1);

    for (position = 0, current_byte_ptr = ptr; position < length; current_byte_ptr++, position++) {
        if (*current_byte_ptr & 0x80) {
            wmem_strbuf_append_unichar(strbuf, UNREPL);
        } else if (!dect_standard_8bits_code_table[*current_byte_ptr]) {
            wmem_strbuf_append_unichar(strbuf, UNREPL);
        } else {
            wmem_strbuf_append_unichar(strbuf, dect_standard_8bits_code_table[*current_byte_ptr]);
        }
    }

    return (uint8_t *)wmem_strbuf_finalize(strbuf);
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
