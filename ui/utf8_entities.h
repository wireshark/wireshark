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
 */

#define UTF8_MIDDLE_DOT                     "\xc2\xb7"      /*  183 /   0xb7 */

#define UTF8_HORIZONTAL_ELLIPSIS        "\xe2\x80\xa6"      /* 8230 / 0x2026 */
#define UTF8_LEFTWARDS_ARROW            "\xe2\x86\x90"      /* 8592 / 0x2190 */
#define UTF8_RIGHTWARDS_ARROW           "\xe2\x86\x92"      /* 8594 / 0x2192 */
#define UTF8_LEFT_RIGHT_ARROW           "\xe2\x86\x94"      /* 8596 / 0x2194 */

#define UTF8_PLACE_OF_INTEREST_SIGN     "\xe2\x8c\x98"      /* 8984 / 0x2318 */
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
