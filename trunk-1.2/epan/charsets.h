/* charsets.h
 * Routines for handling character sets
 *
 * $Id$
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
#ifndef __CHARSETS_H__
#define __CHARSETS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if 0
void ASCII_to_EBCDIC(guint8 *buf, guint bytes);
guint8 ASCII_to_EBCDIC1(guint8 c);
#endif
void EBCDIC_to_ASCII(guint8 *buf, guint bytes);
guint8 EBCDIC_to_ASCII1(guint8 c);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CHARSETS_H__ */
