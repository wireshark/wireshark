/*  hmac.h
 *  
*  
*  HMAC: Keyed-Hashing for Message Authentication
*  
*  See RFC 2104
*
*  Copyright 2007 Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
*
* $Id:$
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

void hmac_md5(const guint8* text,gint text_len, const guint8* key, gint key_len, guint8 digest[16]);
void hmac_sha1(const guint8* text,gint text_len, const guint8* key, gint key_len, guint8 digest[20]);


