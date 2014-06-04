/* packet-tftp.h
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

#ifndef __PACKET_TFTP_H__
#define __PACKET_TFTP_H__

#include <epan/packet.h>

/* When export file data, store list of separate blocks */
typedef struct file_block_t {
  void *data;
  guint length;
} file_block_t;

/* Used for TFTP Export Object feature */
typedef struct _tftp_eo_t {
	guint32  pkt_num;
	gchar    *filename;
	guint32  payload_len;
	GSList   *block_list;
} tftp_eo_t;


#endif /* __PACKET_TFTP_H__ */
