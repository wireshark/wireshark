/* packet-isis.h
 * Defines and such for core isis protcol decode.
 *
 * Stuart Stanley <stuarts@mxmail.net>
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

#ifndef _PACKET_ISIS_H
#define _PACKET_ISIS_H

/*
 * The version we support is 1
 */
#define ISIS_REQUIRED_VERSION 1

/*
 * ISIS type field values
 */
#define ISIS_TYPE_L1_HELLO  15
#define ISIS_TYPE_L2_HELLO  16
#define ISIS_TYPE_PTP_HELLO 17
#define ISIS_TYPE_L1_LSP    18
#define ISIS_TYPE_L2_LSP    20
#define ISIS_TYPE_L1_CSNP   24
#define ISIS_TYPE_L2_CSNP   25
#define ISIS_TYPE_L1_PSNP   26
#define ISIS_TYPE_L2_PSNP   27

#define ISIS_TYPE_MASK 	        0x1f
#define ISIS_TYPE_RESERVED_MASK 0xe0

/*
 * Data given to subdissectors
 */
typedef struct isis_data {
	guint8 header_length;
	guint8 system_id_len;
} isis_data_t;

#endif /* _PACKET_ISIS_H */
