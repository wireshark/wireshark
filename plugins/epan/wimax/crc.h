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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
