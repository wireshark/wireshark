/* utf8_entities.h
 * Byte sequences for various UTF-8 entities
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef __UTF8_ENTITIES_H__
#define __UTF8_ENTITIES_H__

/*
 * Sequences can be found at
 * http://www.fileformat.info/info/unicode/
 * http://www.utf8-chartable.de/
 * and other places
 *
 * While many modern systems default to UTF-8 and handle it well, some do
 * not. The Windows console is a notable example. When adding a glyph below
 * you probably shouldn't stray too far from code page 437 or WGL4:
 * https://en.wikipedia.org/wiki/Code_page_437
 * https://en.wikipedia.org/wiki/Windows_Glyph_List_4
 */

#define UTF8_DEGREE_SIGN                    "\xc2\xb0"      /*   176 /   0xb0 */
#define UTF8_MICRO_SIGN                     "\xc2\xb5"      /*   181 /   0xb5 */
#define UTF8_MIDDLE_DOT                     "\xc2\xb7"      /*   183 /   0xb7 */

#define UTF8_BULLET                     "\xe2\x80\xa2"      /*  8226 / 0x2024 */
#define UTF8_EM_DASH                    "\xe2\x80\x94"      /*  8212 / 0x2014 */
#define UTF8_HORIZONTAL_ELLIPSIS        "\xe2\x80\xa6"      /*  8230 / 0x2026 */

#define UTF8_LEFTWARDS_ARROW            "\xe2\x86\x90"      /*  8592 / 0x2190 */
#define UTF8_RIGHTWARDS_ARROW           "\xe2\x86\x92"      /*  8594 / 0x2192 */
#define UTF8_LEFT_RIGHT_ARROW           "\xe2\x86\x94"      /*  8596 / 0x2194 */

/* OS X command key */
#define UTF8_PLACE_OF_INTEREST_SIGN     "\xe2\x8c\x98"      /*  8984 / 0x2318 */

#define UTF8_SYMBOL_FOR_NULL            "\xe2\x90\x80"      /*  9216 / 0x2400 */

#define UTF8_CHECK_MARK                 "\xe2\x9c\x93"      /* 10003 / 0x2713 */
#define UTF8_BALLOT_X                   "\xe2\x9c\x97"      /* 10007 / 0x2717 */
#define UTF8_LONG_RIGHTWARDS_ARROW      "\xe2\x9f\xb6"      /* 10230 / 0x27f6 */

#define UTF8_ZERO_WIDTH_NO_BREAK_SPACE  "\xef\xbb\xbf"      /* 65279 / 0xffef */
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
