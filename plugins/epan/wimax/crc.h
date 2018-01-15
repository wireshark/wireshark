/* crc.h
 * header file of crc.c
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Mike Harvey <michael.harvey@intel.com>
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

#ifndef CRC_H
#define CRC_H

#include <glib.h>

/* use lookup tables to compute CRC values */
#ifdef STATIC_DATA
extern guint8  crc8_table[];
extern guint32 crc32_table[];
#else
void wimax_mac_gen_crc32_table(void);
void wimax_mac_gen_crc8_table(void);
#endif

guint32 wimax_mac_calc_crc32(const guint8 *data, guint data_len);
guint16 wimax_mac_calc_crc16(const guint8 *data, guint data_len);
guint8 wimax_mac_calc_crc8(const guint8 *data, guint data_len);

#endif /* CRC_H */
