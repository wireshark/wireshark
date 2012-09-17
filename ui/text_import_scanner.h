/**-*-C-*-**********************************************************************
 * text_import_scanner.h
 * Scanner for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.h by Ashok Narayanan <ashokn@cisco.com>
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
 *
 *******************************************************************************/


#ifndef __TEXT_IMPORT_SCANNER_H__
#define __TEXT_IMPORT_SCANNER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    T_BYTE = 1,
    T_OFFSET,
    T_DIRECTIVE,
    T_TEXT,
    T_EOL
} token_t;


void parse_token(token_t token, char *str);
void write_current_packet(void);

extern FILE *text_importin;

int text_importlex(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_SCANNER_H__ */
