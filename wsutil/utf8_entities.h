/** @file
 *
 * Byte sequences for various UTF-8 entities
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __UTF8_ENTITIES_H__
#define __UTF8_ENTITIES_H__

/*
 * Common UTF-8 sequences.
 * Although we've supported UTF-8 encoded source files since April 2019 /
 * bd75f5af0a, it can be useful to explictly encode some code points in
 * order to ensure that we use them consistently.
 *
 * Sequences can be found at
 * http://www.fileformat.info/info/unicode/
 * http://www.utf8-chartable.de/
 * and other places
 *
 * Please be conservative when adding code points below. While many modern
 * systems default to UTF-8 and handle it well, some do not. The Windows
 * console is a notable example. As a general rule you probably shouldn't
 * stray too far from code page 437 or WGL4:
 * https://en.wikipedia.org/wiki/Code_page_437
 * https://en.wikipedia.org/wiki/Windows_Glyph_List_4
 */

#define UTF8_DEGREE_SIGN                    "\u00b0"      /*   176 /   0xb0 */
#define UTF8_SUPERSCRIPT_TWO                "\u00b2"      /*   178 /   0xb2 */
#define UTF8_MICRO_SIGN                     "\u00b5"      /*   181 /   0xb5 */
#define UTF8_MIDDLE_DOT                     "\u00b7"      /*   183 /   0xb7 */
#define UTF8_RIGHT_POINTING_DOUBLE_ANGLE_QUOTATION_MARK "\u00bb" /* 187 / 0xbb */

#define UTF8_CAPITAL_DELTA                  "\u0394"      /*   916 /  0x394 */
#define UTF8_CAPITAL_OMEGA                  "\u03a9"      /*   937 /  0x3a9 */
#define UTF8_OMEGA                          "\u03c9"      /*   969 /  0x3c9 */

#define UTF8_BULLET                     "\u2024"      /*  8226 / 0x2024 */
#define UTF8_EM_DASH                    "\u2014"      /*  8212 / 0x2014 */
#define UTF8_HORIZONTAL_ELLIPSIS        "\u2026"      /*  8230 / 0x2026 */

#define UTF8_SUBSCRIPT_ZERO             "\u2080"      /*  8320 / 0x2080 */

#define UTF8_LEFTWARDS_ARROW            "\u2190"      /*  8592 / 0x2190 */
#define UTF8_RIGHTWARDS_ARROW           "\u2192"      /*  8594 / 0x2192 */
#define UTF8_LEFT_RIGHT_ARROW           "\u2194"      /*  8596 / 0x2194 */

#define UTF8_SQUARE_ROOT                "\u221a"      /*  8730 / 0x221a */

/* macOS command key */
#define UTF8_PLACE_OF_INTEREST_SIGN     "\u2318"      /*  8984 / 0x2318 */

#define UTF8_SYMBOL_FOR_NULL            "\u2400"      /*  9216 / 0x2400 */

#define UTF8_CHECK_MARK                 "\u2713"      /* 10003 / 0x2713 */
#define UTF8_BALLOT_X                   "\u2717"      /* 10007 / 0x2717 */
#define UTF8_LONG_RIGHTWARDS_ARROW      "\u27f6"      /* 10230 / 0x27f6 */

#define UTF8_ZERO_WIDTH_NO_BREAK_SPACE  "\ufeff"      /* 65279 / 0xfeff */
#define UTF8_BOM UTF8_ZERO_WIDTH_NO_BREAK_SPACE

#endif /* __UTF8_ENTITIES_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */
