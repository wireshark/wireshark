/* utf8_entities.h
 * Byte sequences for various UTF-8 entities
 *
 * $Id: utf8_entities.h 33816 2010-08-16 17:53:43Z gerald $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef __UTF8_ENTITIES_H__
#define __UTF8_ENTITIES_H__

/*
 * Sequences can be found at
 * http://www.fileformat.info/info/unicode/
 * http://www.utf8-chartable.de/
 * and other places
 */

#define UTF8_HORIZONTAL_ELLIPSIS        "\xe2\x80\xa6"
#define UTF8_LEFTWARDS_ARROW	        "\xe2\x86\x90"
#define UTF8_RIGHTWARDS_ARROW   	"\xe2\x86\x92"
#define UTF8_LEFT_RIGHT_ARROW   	"\xe2\x86\x94"

#endif /* __UTF8_ENTITIES_H__ */
