/* packet-imf.h
 * Routines for Internet Message Format (IMF) packet disassembly
 *
 * Copyright (c) 2007 by Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#ifndef __PACKET_IMF_H__
#define __PACKET_IMF_H__

#include <epan/packet.h>

/* Find the end of the next IMF field in the tvb.
 * This is not necessarily the first \r\n as there may be continuation lines.
 *
 * If we have found the last field (terminated by \r\n\r\n) we indicate this in last_field .
 */
int imf_find_field_end(tvbuff_t *tvb, int offset, gint max_length, gboolean *last_field);

/* Used for IMF Export Object feature */
typedef struct _imf_eo_t {
  gchar    *filename;
  gchar    *sender_data;
  gchar    *subject_data;
  guint32  payload_len;
  gchar    *payload_data;
} imf_eo_t;

#endif /* __PACKET_IMF_H__ */
